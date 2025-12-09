const express = require('express');
const router = express.Router();
const XLSX = require('xlsx');
const path = require('path');
const fs = require('fs');
const MasterDataVai = require('../models/MasterDataVai');
const KichThuoc = require('../models/KichThuoc');

// Middleware để kiểm tra authentication
// Kiểm tra xem request có phải là API call không (có header Accept: application/json hoặc path bắt đầu bằng /api)
function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
    // Nếu là API call, trả về JSON. Nếu không, redirect
    const isApiCall = req.path.startsWith('/api') || req.headers.accept?.includes('application/json');
    if (isApiCall) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Please login.' });
    }
    return res.redirect('/login');
}

function requireWarehouseAccess(req, res, next) {
    if (req.session && req.session.user) {
        const role = req.session.user.role;
        if (role === 'warehouse_staff' || role === 'warehouse_manager' || role === 'admin') {
            return next();
        }
    }
    return res.status(403).json({ success: false, message: 'Access denied. Warehouse access required.' });
}

// Hàm utility để parse cao và ngang từ kích thước
// Hỗ trợ các format: 
// - "30cm x 40cm", "30x40", "30cmx40cm", "30 x 40", "30cm x40cm"
// - "Ngang1m5xCao2m", "ngang150xcao200", "Ngang1.5m x Cao2m"
// - "1m5x2m", "1.5m x 2m"
function parseCaoNgangFromKichThuoc(kichThuoc) {
    if (!kichThuoc || typeof kichThuoc !== 'string') {
        return { cao: null, ngang: null };
    }

    // Loại bỏ khoảng trắng thừa và chuyển về lowercase
    const cleaned = kichThuoc.trim().toLowerCase();
    
    // Pattern 1: "Ngang1m5xCao2m" hoặc "ngang150xcao200" hoặc "Ngang1.5m x Cao2m"
    // Tìm "ngang" + số + đơn vị + "x" + "cao" + số + đơn vị
    const patternNgangCao = /ngang\s*(\d+(?:\.\d+)?)\s*(?:m|cm)?\s*(?:(\d+))?\s*x\s*cao\s*(\d+(?:\.\d+)?)\s*(?:m|cm)?/i;
    const matchNgangCao = cleaned.match(patternNgangCao);
    
    if (matchNgangCao) {
        let ngang = parseFloat(matchNgangCao[1]);
        // Nếu có số thứ 2 (ví dụ: 1m5 = 1.5m)
        if (matchNgangCao[2]) {
            ngang = ngang + parseFloat('0.' + matchNgangCao[2]);
        }
        // Chuyển về cm nếu là m
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            ngang = ngang * 100;
        }
        
        let cao = parseFloat(matchNgangCao[3]);
        // Chuyển về cm nếu là m
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            cao = cao * 100;
        }
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }
    
    // Pattern 2: "1m5x2m" hoặc "1.5m x 2m" (format ngắn gọn)
    // Tìm số + m + số (tùy chọn) + x + số + m
    const patternShort = /(\d+)\s*m\s*(\d+)?\s*x\s*(\d+)\s*m/i;
    const matchShort = cleaned.match(patternShort);
    
    if (matchShort) {
        let ngang = parseFloat(matchShort[1]);
        if (matchShort[2]) {
            ngang = ngang + parseFloat('0.' + matchShort[2]);
        }
        ngang = ngang * 100; // Chuyển về cm
        
        let cao = parseFloat(matchShort[3]) * 100; // Chuyển về cm
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }
    
    // Pattern 3: "30cm x 40cm" hoặc "30cmx40cm" hoặc "30 x 40"
    const pattern1 = /(\d+(?:\.\d+)?)\s*(?:cm|m)?\s*x\s*(\d+(?:\.\d+)?)\s*(?:cm|m)?/i;
    const match1 = cleaned.match(pattern1);
    
    if (match1) {
        let cao = parseFloat(match1[1]);
        let ngang = parseFloat(match1[2]);
        
        // Chuyển về cm nếu là m
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            cao = cao * 100;
            ngang = ngang * 100;
        }
        
        return { cao: cao.toString(), ngang: ngang.toString() };
    }

    // Pattern 4: "30x40" (không có đơn vị, giả định là cm)
    const pattern2 = /(\d+(?:\.\d+)?)\s*x\s*(\d+(?:\.\d+)?)/i;
    const match2 = cleaned.match(pattern2);
    
    if (match2) {
        const cao = parseFloat(match2[1]);
        const ngang = parseFloat(match2[2]);
        return { cao: cao.toString(), ngang: ngang.toString() };
    }

    return { cao: null, ngang: null };
}

// POST /api/export-nhap-phoi - Handles exporting data to an Excel file
router.post('/', requireLogin, requireWarehouseAccess, async (req, res) => {
    const { items } = req.body;

    if (!items || !Array.isArray(items)) {
        return res.status(400).json({ success: false, message: 'Invalid data format.' });
    }

    try {
        const templatePath = path.join(__dirname, '..', 'uploads', 'template', 'nhap_phoi_template.xlsx');
        
        // Check if template file exists
        if (!fs.existsSync(templatePath)) {
            console.error('Template file not found at:', templatePath);
            return res.status(500).json({ success: false, message: 'Template file not found.' });
        }

        const workbook = XLSX.readFile(templatePath);
        const sheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[sheetName];

        // Start writing from row 2 (index 1), assuming row 1 is headers
        const startRow = 1;
        const exportRows = [];

        // Xử lý từng item để lấy SKU từ MasterDataVai
        for (const item of items) {
            let sku = item.szSku || ''; // Fallback về szSku nếu không tìm thấy
            const maMau = item.maMau; // Lấy maMau từ item
            
            if (!maMau) {
                console.warn('Item thiếu maMau:', item);
                exportRows.push({
                    sku: sku,
                    soLuong: item.soLuong || 0
                });
                continue;
            }
            
            // Bước 1: Lấy thông tin kích thước từ KichThuoc collection bằng szSku
            if (item.szSku) {
                const kichThuocData = await KichThuoc.findOne({ szSku: item.szSku });
                
                if (kichThuocData && kichThuocData.kichThuoc) {
                    // Bước 2: Parse cao và ngang từ kích thước
                    const { cao, ngang } = parseCaoNgangFromKichThuoc(kichThuocData.kichThuoc);
                    
                    if (cao && ngang) {
                        // Bước 3: Tìm SKU từ MasterDataVai bằng Mẫu + cao + ngang
                        const masterData = await MasterDataVai.findOne({
                            mau: maMau,
                            cao: cao.toString(),
                            ngang: ngang.toString()
                        });
                        
                        if (masterData && masterData.sku) {
                            sku = masterData.sku;
                        } else {
                            console.warn(`Không tìm thấy SKU trong MasterDataVai cho Mẫu: ${maMau}, Cao: ${cao}, Ngang: ${ngang}, szSku: ${item.szSku}`);
                        }
                    } else {
                        console.warn(`Không parse được cao/ngang từ kích thước: ${kichThuocData.kichThuoc}, szSku: ${item.szSku}`);
                    }
                } else {
                    console.warn(`Không tìm thấy kích thước với szSku: ${item.szSku}`);
                }
            } else {
                console.warn('Item thiếu szSku:', item);
            }
            
            exportRows.push({
                sku: sku,
                soLuong: item.soLuong || 0
            });
        }

        // Ghi vào Excel
        exportRows.forEach((row, index) => {
            const rowIndex = startRow + index;
            // Column C for SKU, Column D for Quantity
            XLSX.utils.sheet_add_aoa(worksheet, [[row.sku, row.soLuong]], { origin: `C${rowIndex + 1}` });
        });

        const outputBuffer = XLSX.write(workbook, { bookType: 'xlsx', type: 'buffer' });

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `NhapPhoi_Export_${timestamp}.xlsx`;

        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.send(outputBuffer);

    } catch (error) {
        console.error('Error exporting to Excel:', error);
        res.status(500).json({ success: false, message: 'Failed to export data.', error: error.message });
    }
});

module.exports = router;
