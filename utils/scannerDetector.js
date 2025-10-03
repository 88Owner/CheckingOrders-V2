const { SerialPort } = require('serialport');
const Account = require('../models/Account');

/**
 * Cache để lưu kết quả quét cổng, tránh quét liên tục
 */
let cachedPorts = [];
let lastScanTime = null;
const CACHE_DURATION = 10000; // 10 giây

/**
 * Phát hiện tất cả cổng serial đang kết nối
 */
async function detectAllSerialPorts() {
    try {
        console.log('[detectAllSerialPorts] Bắt đầu quét cổng serial...');
        const ports = await SerialPort.list();
        console.log(`[detectAllSerialPorts] SerialPort.list() trả về ${ports.length} cổng`);
        
        if (ports.length === 0) {
            console.warn('[detectAllSerialPorts] CẢNH BÁO: Không tìm thấy cổng serial nào!');
            console.warn('[detectAllSerialPorts] Kiểm tra:');
            console.warn('  - Máy quét đã được cắm vào USB?');
            console.warn('  - Driver đã được cài đặt?');
            console.warn('  - Có quyền truy cập serial port?');
            return [];
        }
        
        const mappedPorts = ports.map(port => {
            console.log(`[detectAllSerialPorts] Port: ${port.path}, Manufacturer: ${port.manufacturer || 'Unknown'}, VID: ${port.vendorId}, PID: ${port.productId}`);
            return {
                path: port.path,
                manufacturer: port.manufacturer || 'Unknown',
                vendorId: port.vendorId || null,
                productId: port.productId || null,
                serialNumber: port.serialNumber || null,
                pnpId: port.pnpId || null,
                locationId: port.locationId || null
            };
        });
        
        console.log(`[detectAllSerialPorts] Trả về ${mappedPorts.length} cổng serial`);
        return mappedPorts;
    } catch (error) {
        console.error('[detectAllSerialPorts] LỖI khi phát hiện cổng serial:', error);
        console.error('[detectAllSerialPorts] Stack:', error.stack);
        return [];
    }
}

/**
 * Kiểm tra xem cổng có phải là máy quét barcode/QR không
 * Dựa vào manufacturer name hoặc product ID
 */
function isScannerPort(port) {
    const scannerKeywords = [
        'scanner', 'barcode', 'honeywell', 'symbol', 'zebra', 
        'datalogic', 'cognex', 'code', 'reader', 'qr',
        'usb', 'hid', 'serial'
    ];
    
    const manufacturerLower = (port.manufacturer || '').toLowerCase();
    const pnpIdLower = (port.pnpId || '').toLowerCase();
    
    // Kiểm tra manufacturer name
    for (const keyword of scannerKeywords) {
        if (manufacturerLower.includes(keyword) || pnpIdLower.includes(keyword)) {
            return true;
        }
    }
    
    // Nếu có vendorId/productId thì cũng coi là thiết bị nối tiếp khả dụng
    if (port.vendorId && port.productId) {
        return true;
    }
    
    return false;
}

/**
 * Phát hiện máy quét keyboard khả dụng (chưa được phân quyền cho user nào)
 */
async function detectAvailableScanners() {
    try {
        // Kiểm tra cache
        const now = Date.now();
        if (cachedPorts.length > 0 && lastScanTime && (now - lastScanTime) < CACHE_DURATION) {
            console.log('📦 Sử dụng cached ports (', cachedPorts.length, 'ports)');
            return cachedPorts;
        }
        
        console.log('🔍 Bắt đầu quét cổng máy quét...');
        
        // Phát hiện tất cả cổng serial
        const allPorts = await detectAllSerialPorts();
        console.log('📡 Tìm thấy', allPorts.length, 'cổng serial');
        
        // Lọc ra các cổng có khả năng là máy quét
        const potentialScanners = allPorts.filter(port => {
            // Chấp nhận tất cả cổng để user có thể chọn
            // Hoặc lọc theo điều kiện: isScannerPort(port)
            return true; // Cho phép tất cả các cổng
        });
        
        console.log('🎯 Phát hiện', potentialScanners.length, 'cổng khả dụng');
        
        let assignedPortPaths = new Set();
        
        try {
            // Kiểm tra cổng nào đã được phân quyền
            const assignedPorts = await Account.find({
                'scannerPermissions.port': { $exists: true, $ne: null }
            }, { username: 1, 'scannerPermissions.port': 1 }).maxTimeMS(5000);
            
            assignedPorts.forEach(acc => {
                if (acc.scannerPermissions?.port) {
                    assignedPortPaths.add(acc.scannerPermissions.port);
                }
            });
            
            // Kiểm tra cổng nào đã được assign trong allowedPorts
            const accountsWithAllowedPorts = await Account.find({
                'scannerPermissions.allowedPorts': { $exists: true, $ne: [] }
            }, { username: 1, 'scannerPermissions.allowedPorts': 1 }).maxTimeMS(5000);
            
            for (const acc of accountsWithAllowedPorts) {
                if (acc.scannerPermissions?.allowedPorts) {
                    acc.scannerPermissions.allowedPorts.forEach(port => {
                        assignedPortPaths.add(port);
                    });
                }
            }
            
            console.log('🔒 Cổng đã được phân quyền:', Array.from(assignedPortPaths));
        } catch (dbError) {
            console.warn('⚠️  Không thể kiểm tra DB (có thể chưa kết nối):', dbError.message);
            console.log('📦 Trả về tất cả cổng (không lọc theo phân quyền)');
        }
        
        // Lọc ra các cổng chưa được phân quyền
        const availableScanners = potentialScanners
            .filter(port => !assignedPortPaths.has(port.path))
            .map(port => {
                const isLikelyScanner = isScannerPort(port);
                return {
                    path: port.path,
                    manufacturer: port.manufacturer,
                    vendorId: port.vendorId,
                    productId: port.productId,
                    serialNumber: port.serialNumber,
                    pnpId: port.pnpId,
                    deviceType: isLikelyScanner ? 'Scanner (detected)' : 'Serial Device',
                    status: 'available',
                    confidence: isLikelyScanner ? 'high' : 'medium',
                    note: isLikelyScanner 
                        ? 'Thiết bị có khả năng cao là máy quét' 
                        : 'Thiết bị nối tiếp, có thể là máy quét'
                };
            });
        
        // Cập nhật cache
        cachedPorts = availableScanners;
        lastScanTime = now;
        
        console.log('✅ Tìm thấy', availableScanners.length, 'máy quét khả dụng (chưa được phân quyền)');
        
        return availableScanners;
    } catch (error) {
        console.error('❌ Lỗi phát hiện máy quét:', error);
        // Fallback: trả về tất cả cổng serial nếu có lỗi
        try {
            const allPorts = await detectAllSerialPorts();
            return allPorts.map(port => ({
                path: port.path,
                manufacturer: port.manufacturer,
                vendorId: port.vendorId,
                productId: port.productId,
                serialNumber: port.serialNumber,
                pnpId: port.pnpId,
                deviceType: 'Serial Device',
                status: 'available',
                confidence: 'medium',
                note: 'Phát hiện được nhưng chưa kiểm tra phân quyền'
            }));
        } catch (fallbackError) {
            console.error('❌ Lỗi fallback:', fallbackError);
            return [];
        }
    }
}

/**
 * Xóa cache để force refresh
 */
function clearCache() {
    cachedPorts = [];
    lastScanTime = null;
    console.log('🗑️ Đã xóa cache phát hiện cổng');
}

/**
 * Kiểm tra xem cổng có đang được sử dụng không
 */
async function isPortInUse(portPath) {
    try {
        const account = await Account.findOne({
            $or: [
                { 'scannerPermissions.port': portPath },
                { 'scannerPermissions.allowedPorts': portPath }
            ]
        });
        return !!account;
    } catch (error) {
        console.error('❌ Lỗi kiểm tra port in use:', error);
        return false;
    }
}

/**
 * Lấy thông tin chi tiết về cổng
 */
async function getPortDetails(portPath) {
    try {
        const allPorts = await detectAllSerialPorts();
        const port = allPorts.find(p => p.path === portPath);
        
        if (!port) {
            return null;
        }
        
        const inUse = await isPortInUse(portPath);
        
        return {
            ...port,
            isInUse: inUse,
            status: inUse ? 'in-use' : 'available'
        };
    } catch (error) {
        console.error('❌ Lỗi lấy thông tin port:', error);
        return null;
    }
}

module.exports = {
    detectAllSerialPorts,
    detectAvailableScanners,
    isScannerPort,
    isPortInUse,
    getPortDetails,
    clearCache
}; 