const express = require('express');
const router = express.Router();
const XLSX = require('xlsx');
const path = require('path');
const fs = require('fs');
const MasterDataVai = require('../models/MasterDataVai');
const KichThuoc = require('../models/KichThuoc');
const MauVai = require('../models/MauVai');

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
    
    // Pattern 1: "Ngang1m5xCao2m" hoặc "ngang1m5xcao2m" (format không có khoảng trắng)
    // Tìm "ngang" + số + "m" + số (tùy chọn) + "x" + "cao" + số + "m" + số (tùy chọn)
    // \s* là optional để hỗ trợ cả có và không có khoảng trắng
    const patternNgangCaoCompact = /ngang\s*(\d+)\s*m\s*(\d+)?\s*x\s*cao\s*(\d+)\s*m\s*(\d+)?/i;
    const matchNgangCaoCompact = cleaned.match(patternNgangCaoCompact);
    
    if (matchNgangCaoCompact) {
        let ngang = parseFloat(matchNgangCaoCompact[1]);
        // Nếu có số thứ 2 (ví dụ: 1m5 = 1.5m)
        if (matchNgangCaoCompact[2]) {
            ngang = ngang + parseFloat('0.' + matchNgangCaoCompact[2]);
        }
        ngang = ngang * 100; // Chuyển về cm
        
        let cao = parseFloat(matchNgangCaoCompact[3]);
        // Nếu có số thứ 4 (ví dụ: 2m0 = 2.0m)
        if (matchNgangCaoCompact[4]) {
            cao = cao + parseFloat('0.' + matchNgangCaoCompact[4]);
        }
        cao = cao * 100; // Chuyển về cm
        
        // Chuẩn hóa: loại bỏ phần thập phân không cần thiết (ví dụ: 200.0 -> 200)
        return { cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''), ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '') };
    }
    
    // Pattern 2: "Ngang150xcao200" hoặc "ngang1.5m x cao2m" (format có khoảng trắng hoặc số thập phân)
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
        
        // Chuẩn hóa: loại bỏ phần thập phân không cần thiết
        return { cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''), ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '') };
    }
    
    // Pattern 3: "1m5x2m" hoặc "1.5m x 2m" (format ngắn gọn)
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
        
        // Chuẩn hóa: loại bỏ phần thập phân không cần thiết
        return { cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''), ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '') };
    }
    
    // Pattern 4: "30cm x 40cm" hoặc "30cmx40cm" hoặc "30 x 40"
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
        
        // Chuẩn hóa: loại bỏ phần thập phân không cần thiết
        return { cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''), ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '') };
    }

    // Pattern 5: "30x40" (không có đơn vị, giả định là cm)
    const pattern2 = /(\d+(?:\.\d+)?)\s*x\s*(\d+(?:\.\d+)?)/i;
    const match2 = cleaned.match(pattern2);
    
    if (match2) {
        const cao = parseFloat(match2[1]);
        const ngang = parseFloat(match2[2]);
        // Chuẩn hóa: loại bỏ phần thập phân không cần thiết
        return { cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''), ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '') };
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
            const maMau = item.maMau; // Lấy maMau từ item (maMau phải khớp với "mau" trong MasterDataVai)
            
            if (!maMau) {
                console.warn('⚠️ Item thiếu maMau:', item);
                exportRows.push({
                    sku: sku,
                    soLuong: item.soLuong || 0
                });
                continue;
            }
            
            // Bước 0: Lấy tenMau từ MauVai dựa trên maMau
            // Trong MasterDataVai, trường "mau" lưu tenMau chứ không phải maMau
            const mauVaiData = await MauVai.findOne({ maMau: maMau });
            const tenMau = mauVaiData ? mauVaiData.tenMau : null;
            
            if (!tenMau) {
                console.warn(`⚠️ Không tìm thấy tenMau cho maMau: ${maMau}`);
                // Vẫn thử với maMau như cũ
            }
            
            // Bước 1: Lấy thông tin kích thước từ KichThuoc collection bằng szSku
            if (item.szSku) {
                const kichThuocData = await KichThuoc.findOne({ szSku: item.szSku });
                
                if (kichThuocData && kichThuocData.kichThuoc) {
                    // Bước 2: Parse cao và ngang từ kích thước
                    const { cao, ngang } = parseCaoNgangFromKichThuoc(kichThuocData.kichThuoc);
                    
                    if (cao && ngang) {
                        // Bước 3: cao và ngang đã được chuẩn hóa trong hàm parse (loại bỏ .0)
                        // Chuẩn hóa tenMau để so sánh (trim và loại bỏ khoảng trắng thừa)
                        const tenMauNormalized = tenMau ? String(tenMau || '').trim() : String(maMau || '').trim();
                        const caoNormalized = String(cao || '').trim();
                        const ngangNormalized = String(ngang || '').trim();
                        
                        // Tìm SKU từ MasterDataVai bằng Mẫu (tenMau) + cao + ngang
                        // Thử nhiều cách query để đảm bảo tìm thấy
                        let masterData = null;
                        
                        // Cách 1: Query chính xác với tenMau
                        masterData = await MasterDataVai.findOne({
                            mau: tenMauNormalized,
                            cao: caoNormalized,
                            ngang: ngangNormalized
                        });
                        
                        // Cách 2: Nếu không tìm thấy, thử với regex không phân biệt hoa thường cho mau
                        if (!masterData) {
                            masterData = await MasterDataVai.findOne({
                                mau: { $regex: new RegExp(`^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
                                cao: caoNormalized,
                                ngang: ngangNormalized
                            });
                        }
                        
                        // Cách 3: Thử đảo ngược cao/ngang (có thể bị nhầm trong MasterDataVai)
                        if (!masterData) {
                            masterData = await MasterDataVai.findOne({
                                mau: { $regex: new RegExp(`^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
                                cao: ngangNormalized,
                                ngang: caoNormalized
                            });
                        }
                        
                        // Cách 4: Thử với số nguyên (loại bỏ phần thập phân)
                        if (!masterData) {
                            const caoInt = Math.round(parseFloat(caoNormalized)).toString();
                            const ngangInt = Math.round(parseFloat(ngangNormalized)).toString();
                            masterData = await MasterDataVai.findOne({
                                mau: { $regex: new RegExp(`^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
                                $or: [
                                    { cao: caoInt, ngang: ngangInt },
                                    { cao: caoNormalized, ngang: ngangNormalized },
                                    { cao: ngangInt, ngang: caoInt }
                                ]
                            });
                        }
                        
                        // Cách 5: Nếu vẫn không tìm thấy với tenMau, thử với maMau (fallback)
                        if (!masterData && tenMau) {
                            const maMauNormalized = String(maMau || '').trim();
                            masterData = await MasterDataVai.findOne({
                                mau: { $regex: new RegExp(`^${maMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
                                cao: caoNormalized,
                                ngang: ngangNormalized
                            });
                        }
                        
                        if (masterData && masterData.sku) {
                            sku = masterData.sku;
                            console.log(`✅ Tìm thấy SKU: ${sku} cho Mẫu (tenMau): ${tenMauNormalized} (maMau: ${maMau}), Cao: ${caoNormalized}, Ngang: ${ngangNormalized}, kichThuoc: ${kichThuocData.kichThuoc}`);
                        } else {
                            // KHÔNG fallback về szSku - phải tìm thấy SKU từ MasterDataVai
                            console.error(`❌ KHÔNG TÌM THẤY SKU trong MasterDataVai cho Mẫu (tenMau): ${tenMauNormalized} (maMau: ${maMau}), Cao: ${caoNormalized}, Ngang: ${ngangNormalized}, szSku: ${item.szSku}, kichThuoc: ${kichThuocData.kichThuoc}`);
                            
                            // Log thêm để debug: xem có dữ liệu nào trong MasterDataVai với mau này không
                            const sampleData = await MasterDataVai.findOne({ mau: { $regex: new RegExp(`^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } });
                            if (sampleData) {
                                console.log(`   📋 Mẫu dữ liệu trong MasterDataVai cho mẫu "${tenMauNormalized}": SKU=${sampleData.sku}, Cao=${sampleData.cao}, Ngang=${sampleData.ngang}`);
                                // Thử tìm với các giá trị cao/ngang khác nhau
                                const allMauData = await MasterDataVai.find({ mau: { $regex: new RegExp(`^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } }).limit(10);
                                if (allMauData.length > 0) {
                                    console.log(`   📋 Tất cả dữ liệu MasterDataVai cho mẫu "${tenMauNormalized}" (${allMauData.length} records):`);
                                    allMauData.forEach((data, idx) => {
                                        console.log(`      ${idx + 1}. SKU=${data.sku}, Cao=${data.cao}, Ngang=${data.ngang}`);
                                    });
                                }
                            } else {
                                console.log(`   ⚠️ Không có dữ liệu nào trong MasterDataVai cho mẫu "${tenMauNormalized}"`);
                            }
                            
                            // Đặt sku = '' để báo lỗi rõ ràng thay vì dùng szSku
                            sku = '';
                        }
                    } else {
                        console.warn(`❌ Không parse được cao/ngang từ kích thước: ${kichThuocData.kichThuoc}, szSku: ${item.szSku}`);
                    }
                } else {
                    console.warn(`Không tìm thấy kích thước với szSku: ${item.szSku}`);
                }
            } else {
                console.warn('Item thiếu szSku:', item);
            }
            
            // Chỉ thêm vào exportRows nếu có SKU hợp lệ từ MasterDataVai
            if (sku && sku !== item.szSku) {
                // SKU từ MasterDataVai - OK
                exportRows.push({
                    sku: sku,
                    soLuong: item.soLuong || 0
                });
            } else if (!sku || sku === '') {
                // Không tìm thấy SKU - báo lỗi nhưng vẫn thêm vào để user biết
                console.error(`⚠️ BỎ QUA item vì không tìm thấy SKU: maMau=${item.maMau}, szSku=${item.szSku}, kichThuoc=${item.kichThuoc || 'N/A'}`);
                // Vẫn thêm vào nhưng với SKU rỗng để user biết có vấn đề
                exportRows.push({
                    sku: `[LỖI: Không tìm thấy SKU cho ${item.maMau}]`,
                    soLuong: item.soLuong || 0
                });
            } else {
                // Fallback về szSku chỉ khi thực sự cần thiết (không nên xảy ra)
                console.warn(`⚠️ Sử dụng szSku làm SKU: ${item.szSku} cho maMau: ${item.maMau}`);
                exportRows.push({
                    sku: item.szSku,
                    soLuong: item.soLuong || 0
                });
            }
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
