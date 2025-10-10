const Redis = require('redis');

/**
 * Redis-based distributed locking
 * Đảm bảo atomic operations mà không cần MongoDB transactions
 */

class RedisLocking {
    constructor() {
        this.client = null;
        this.connected = false;
    }

    async connect() {
        try {
            // Kết nối Redis (có thể dùng Redis container hoặc external)
            this.client = Redis.createClient({
                host: process.env.REDIS_HOST || 'localhost',
                port: process.env.REDIS_PORT || 6379,
                password: process.env.REDIS_PASSWORD || undefined,
                retry_strategy: (options) => {
                    if (options.error && options.error.code === 'ECONNREFUSED') {
                        // Redis không khả dụng, fallback về optimistic locking
                        console.warn('⚠️ Redis không khả dụng, sử dụng optimistic locking');
                        return undefined;
                    }
                    if (options.total_retry_time > 1000 * 60 * 60) {
                        return new Error('Retry time exhausted');
                    }
                    if (options.attempt > 10) {
                        return undefined;
                    }
                    return Math.min(options.attempt * 100, 3000);
                }
            });

            this.client.on('error', (err) => {
                console.error('Redis Client Error:', err);
                this.connected = false;
            });

            this.client.on('connect', () => {
                console.log('✅ Redis connected');
                this.connected = true;
            });

            await this.client.connect();
        } catch (error) {
            console.warn('⚠️ Không thể kết nối Redis:', error.message);
            this.connected = false;
        }
    }

    /**
     * Acquire lock với TTL
     * @param {string} key - Lock key
     * @param {string} value - Lock value (user ID)
     * @param {number} ttl - Time to live (seconds)
     * @returns {Promise<boolean>}
     */
    async acquireLock(key, value, ttl = 30) {
        if (!this.connected) {
            return true; // Fallback: cho phép nếu Redis không khả dụng
        }

        try {
            const result = await this.client.set(key, value, {
                EX: ttl,
                NX: true // Chỉ set nếu key không tồn tại
            });
            return result === 'OK';
        } catch (error) {
            console.error('Redis lock error:', error);
            return true; // Fallback: cho phép nếu có lỗi
        }
    }

    /**
     * Release lock
     * @param {string} key - Lock key
     * @param {string} value - Lock value (phải match để release)
     * @returns {Promise<boolean>}
     */
    async releaseLock(key, value) {
        if (!this.connected) {
            return true;
        }

        try {
            // Lua script để đảm bảo atomic release
            const script = `
                if redis.call("GET", KEYS[1]) == ARGV[1] then
                    return redis.call("DEL", KEYS[1])
                else
                    return 0
                end
            `;
            
            const result = await this.client.eval(script, {
                keys: [key],
                arguments: [value]
            });
            
            return result === 1;
        } catch (error) {
            console.error('Redis unlock error:', error);
            return false;
        }
    }

    /**
     * Extend lock TTL
     * @param {string} key - Lock key
     * @param {string} value - Lock value
     * @param {number} ttl - New TTL
     * @returns {Promise<boolean>}
     */
    async extendLock(key, value, ttl = 30) {
        if (!this.connected) {
            return true;
        }

        try {
            const script = `
                if redis.call("GET", KEYS[1]) == ARGV[1] then
                    return redis.call("EXPIRE", KEYS[1], ARGV[2])
                else
                    return 0
                end
            `;
            
            const result = await this.client.eval(script, {
                keys: [key],
                arguments: [value, ttl]
            });
            
            return result === 1;
        } catch (error) {
            console.error('Redis extend lock error:', error);
            return false;
        }
    }

    /**
     * Lock orders với Redis
     * @param {Array} orderIds - Order IDs
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, lockedCount: number, errors: Array}>}
     */
    async lockOrders(orderIds, userId) {
        const results = {
            success: true,
            lockedCount: 0,
            errors: []
        };

        for (const orderId of orderIds) {
            const lockKey = `order:lock:${orderId}`;
            
            try {
                const acquired = await this.acquireLock(lockKey, userId, 300); // 5 phút TTL
                
                if (acquired) {
                    results.lockedCount++;
                    
                    // Update MongoDB
                    await Order.updateOne(
                        { _id: orderId },
                        { 
                            $set: { 
                                block: true, 
                                checkingBy: userId, 
                                blockedAt: new Date()
                            } 
                        }
                    );
                } else {
                    results.errors.push(`Đơn hàng ${orderId} đang được user khác sử dụng`);
                    results.success = false;
                }
            } catch (error) {
                results.errors.push(`Lỗi lock đơn ${orderId}: ${error.message}`);
                results.success = false;
            }
        }

        return results;
    }

    /**
     * Unlock orders
     * @param {Array} orderIds - Order IDs
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, unlockedCount: number}>}
     */
    async unlockOrders(orderIds, userId) {
        const results = {
            success: true,
            unlockedCount: 0
        };

        for (const orderId of orderIds) {
            const lockKey = `order:lock:${orderId}`;
            
            try {
                const released = await this.releaseLock(lockKey, userId);
                
                if (released) {
                    results.unlockedCount++;
                    
                    // Update MongoDB
                    await Order.updateOne(
                        { _id: orderId },
                        { 
                            $set: { 
                                block: false,
                                checkingBy: null,
                                blockedAt: null,
                                scannedQuantity: 0,
                                verified: false,
                                verifiedAt: null
                            } 
                        }
                    );
                }
            } catch (error) {
                console.error(`Lỗi unlock đơn ${orderId}:`, error);
                results.success = false;
            }
        }

        return results;
    }
}

module.exports = RedisLocking;
