const ComboData = require('../models/ComboData');

class ComboCache {
    constructor() {
        this.cache = new Map();
        this.lastUpdate = null;
        this.cacheTimeout = 5 * 60 * 1000; // 5 phút
        this.isUpdating = false;
    }

    // Lấy tất cả combo data từ cache hoặc database
    async getAllCombos() {
        if (this.shouldRefreshCache()) {
            await this.refreshCache();
        }
        return this.cache;
    }

    // Lấy combo theo comboCode
    async getCombosByCode(comboCode) {
        const allCombos = await this.getAllCombos();
        return allCombos.get(comboCode) || [];
    }

    // Lấy combo theo maHang
    async getCombosByMaHang(maHang) {
        const allCombos = await this.getAllCombos();
        const results = [];
        for (const [comboCode, combos] of allCombos) {
            const matchingCombos = combos.filter(combo => combo.maHang === maHang);
            if (matchingCombos.length > 0) {
                results.push(...matchingCombos);
            }
        }
        return results;
    }

    // Kiểm tra xem có cần refresh cache không
    shouldRefreshCache() {
        if (!this.lastUpdate) return true;
        if (this.cache.size === 0) return true;
        return Date.now() - this.lastUpdate > this.cacheTimeout;
    }

    // Refresh cache từ database
    async refreshCache() {
        if (this.isUpdating) {
            // Nếu đang update, đợi cho đến khi xong
            while (this.isUpdating) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            return;
        }

        this.isUpdating = true;
        try {
            console.log('🔄 Refreshing ComboData cache...');
            const startTime = Date.now();
            
            // Lấy tất cả combo data từ database
            const comboDocs = await ComboData.find({}).lean();
            
            // Group theo comboCode
            const newCache = new Map();
            for (const combo of comboDocs) {
                if (!newCache.has(combo.comboCode)) {
                    newCache.set(combo.comboCode, []);
                }
                newCache.get(combo.comboCode).push(combo);
            }

            // Update cache
            this.cache = newCache;
            this.lastUpdate = Date.now();

            const duration = Date.now() - startTime;
            console.log(`✅ ComboData cache refreshed: ${comboDocs.length} items in ${duration}ms`);
        } catch (error) {
            console.error('❌ Error refreshing ComboData cache:', error);
        } finally {
            this.isUpdating = false;
        }
    }

    // Invalidate cache (gọi khi có thay đổi dữ liệu)
    invalidateCache() {
        console.log('🗑️ Invalidating ComboData cache...');
        this.cache.clear();
        this.lastUpdate = null;
    }

    // Lấy thống kê cache
    getCacheStats() {
        let totalCombos = 0;
        for (const combos of this.cache.values()) {
            totalCombos += combos.length;
        }
        
        return {
            comboCodeCount: this.cache.size,
            totalComboItems: totalCombos,
            lastUpdate: this.lastUpdate,
            isUpdating: this.isUpdating,
            cacheAge: this.lastUpdate ? Date.now() - this.lastUpdate : null
        };
    }
}

// Singleton instance
const comboCache = new ComboCache();

module.exports = comboCache;
