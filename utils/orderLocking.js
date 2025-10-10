const Order = require('../models/Order');

/**
 * Optimistic locking cho Order operations
 * Sử dụng version field để đảm bảo consistency
 */

class OrderLocking {
    /**
     * Block đơn hàng với optimistic locking
     * @param {Array} orderIds - Array of order IDs
     * @param {string} userId - User ID
     * @param {number} maxRetries - Số lần retry tối đa
     * @returns {Promise<{success: boolean, blockedCount: number, errors: Array}>}
     */
    static async blockOrders(orderIds, userId, maxRetries = 3) {
        const results = {
            success: true,
            blockedCount: 0,
            errors: []
        };

        for (const orderId of orderIds) {
            let retryCount = 0;
            let success = false;

            while (retryCount < maxRetries && !success) {
                try {
                    // Tìm đơn hàng với version hiện tại
                    const order = await Order.findById(orderId);
                    
                    if (!order) {
                        results.errors.push(`Đơn hàng ${orderId} không tồn tại`);
                        break;
                    }

                    // Kiểm tra conflict
                    if (order.block && order.checkingBy !== userId) {
                        results.errors.push(`Đơn hàng ${order.maDongGoi} đang được ${order.checkingBy} kiểm tra`);
                        break;
                    }

                    // Update với version check (optimistic locking)
                    const result = await Order.updateOne(
                        { 
                            _id: orderId,
                            // Chỉ update nếu version không thay đổi
                            $or: [
                                { block: false },
                                { checkingBy: userId }
                            ]
                        },
                        { 
                            $set: { 
                                block: true, 
                                checkingBy: userId, 
                                blockedAt: new Date(),
                                version: (order.version || 0) + 1
                            } 
                        }
                    );

                    if (result.modifiedCount > 0) {
                        results.blockedCount++;
                        success = true;
                    } else {
                        retryCount++;
                        if (retryCount < maxRetries) {
                            // Wait một chút trước khi retry
                            await new Promise(resolve => setTimeout(resolve, 100 * retryCount));
                        }
                    }

                } catch (error) {
                    results.errors.push(`Lỗi block đơn ${orderId}: ${error.message}`);
                    break;
                }
            }

            if (!success && retryCount >= maxRetries) {
                results.errors.push(`Không thể block đơn ${orderId} sau ${maxRetries} lần thử`);
                results.success = false;
            }
        }

        return results;
    }

    /**
     * Unblock đơn hàng
     * @param {string} maVanDon - Mã vận đơn
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, unblockedCount: number}>}
     */
    static async unblockOrders(maVanDon, userId) {
        try {
            const result = await Order.updateMany(
                { 
                    maVanDon: maVanDon,
                    checkingBy: userId, 
                    block: true 
                },
                { 
                    $set: { 
                        checkingBy: null,
                        block: false,
                        blockedAt: null,
                        scannedQuantity: 0,
                        verified: false,
                        verifiedAt: null,
                        version: { $inc: 1 } // Increment version
                    } 
                }
            );

            return {
                success: true,
                unblockedCount: result.modifiedCount
            };
        } catch (error) {
            console.error('❌ [UNLOCK-ERROR] Failed to unlock orders:', error.message);
            return {
                success: false,
                unblockedCount: 0,
                error: error.message
            };
        }
    }

    /**
     * Kiểm tra trạng thái lock của đơn hàng
     * @param {Array} orderIds - Array of order IDs
     * @returns {Promise<Object>}
     */
    static async checkLockStatus(orderIds) {
        try {
            const orders = await Order.find(
                { _id: { $in: orderIds } },
                { _id: 1, block: 1, checkingBy: 1, maDongGoi: 1 }
            );

            const status = {
                total: orders.length,
                blocked: 0,
                available: 0,
                conflicts: []
            };

            orders.forEach(order => {
                if (order.block) {
                    status.blocked++;
                    status.conflicts.push({
                        orderId: order._id,
                        maDongGoi: order.maDongGoi,
                        checkingBy: order.checkingBy
                    });
                } else {
                    status.available++;
                }
            });

            return status;
        } catch (error) {
            console.error('❌ [LOCK-STATUS-ERROR]:', error.message);
            throw error;
        }
    }
}

module.exports = OrderLocking;
