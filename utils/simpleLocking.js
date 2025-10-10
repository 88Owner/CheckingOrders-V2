const Order = require('../models/Order');

/**
 * Simple Locking - Không cần version field, chỉ dùng MongoDB operations
 * Đảm bảo logic nghiệp vụ như cũ mà không cần transaction
 */

class SimpleLocking {
    /**
     * Block orders
     * @param {Array} orderIds - Array of order IDs
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, blockedCount: number, errors: Array}>}
     */
    static async blockOrders(orderIds, userId) {
        const results = {
            success: true,
            blockedCount: 0,
            errors: []
        };

        for (const orderId of orderIds) {
            try {
                // Sử dụng findOneAndUpdate để đảm bảo atomic operation
                const result = await Order.findOneAndUpdate(
                    { 
                        _id: orderId,
                        $or: [
                            { block: false },
                            { checkingBy: userId }
                        ]
                    },
                    { 
                        $set: { 
                            block: true, 
                            checkingBy: userId, 
                            blockedAt: new Date()
                        }
                    },
                    { 
                        new: false, // Return original document
                        runValidators: false
                    }
                );

                if (result) {
                    results.blockedCount++;
                    console.log(`✅ Blocked order ${result.maDongGoi || orderId} for user ${userId}`);
                } else {
                    // Kiểm tra tại sao không update được
                    const existingOrder = await Order.findById(orderId);
                    if (!existingOrder) {
                        results.errors.push(`Đơn hàng ${orderId} không tồn tại`);
                    } else if (existingOrder.block && existingOrder.checkingBy !== userId) {
                        results.errors.push(`Đơn hàng ${existingOrder.maDongGoi || orderId} đang được ${existingOrder.checkingBy} kiểm tra`);
                    } else {
                        results.errors.push(`Đơn hàng ${orderId} không thể block`);
                    }
                    results.success = false;
                }

            } catch (error) {
                results.errors.push(`Lỗi block đơn ${orderId}: ${error.message}`);
                results.success = false;
            }
        }

        return results;
    }

    /**
     * Unblock orders
     * @param {string} maVanDon - Mã vận đơn
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, unblockedCount: number}>}
     */
    static async unblockOrders(maVanDon, userId) {
        try {
            // Unblock tất cả đơn hàng mà user hiện tại đang check
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
                        // Reset trạng thái quét khi unlock
                        scannedQuantity: 0,
                        verified: false,
                        verifiedAt: null
                    } 
                }
            );

            console.log(`✅ Unblocked ${result.modifiedCount} orders for user ${userId}`);

            return {
                success: true,
                unblockedCount: result.modifiedCount,
                errors: []
            };

        } catch (error) {
            console.error('❌ [UNLOCK-ERROR] Failed to unlock orders:', error.message);
            return {
                success: false,
                unblockedCount: 0,
                errors: [error.message]
            };
        }
    }

    /**
     * Block single order
     * @param {string} orderId - Order ID
     * @param {string} userId - User ID
     * @returns {Promise<{success: boolean, error?: string}>}
     */
    static async blockSingleOrder(orderId, userId) {
        try {
            // Kiểm tra conflict trước
            const existingOrder = await Order.findById(orderId);
            if (!existingOrder) {
                return { success: false, error: `Đơn hàng ${orderId} không tồn tại` };
            }

            if (existingOrder.block && existingOrder.checkingBy !== userId) {
                return { 
                    success: false, 
                    error: `Đơn hàng ${existingOrder.maDongGoi || orderId} đang được ${existingOrder.checkingBy} kiểm tra` 
                };
            }

            // Block đơn hàng
            const result = await Order.updateOne(
                { 
                    _id: orderId,
                    $or: [
                        { block: false },
                        { checkingBy: userId }
                    ]
                },
                { 
                    $set: { 
                        block: true, 
                        checkingBy: userId, 
                        blockedAt: new Date()
                    } 
                }
            );

            if (result.modifiedCount > 0) {
                console.log(`✅ Blocked single order ${existingOrder.maDongGoi || orderId} for user ${userId}`);
                return { success: true };
            } else {
                return { success: false, error: `Không thể block đơn ${orderId}` };
            }

        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Kiểm tra trạng thái lock của orders
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

module.exports = SimpleLocking;
