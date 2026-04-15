const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const XLSX = require('xlsx');
const MasterDataVai = require('../models/MasterDataVai');
const KichThuoc = require('../models/KichThuoc');
const MauVai = require('../models/MauVai');
const Template = require('../models/Template');
const NhapPhoi = require('../models/NhapPhoi');
const DoiTuongCatVai = require('../models/DoiTuongCatVai');

function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    }
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

function parseCaoNgangFromKichThuoc(kichThuoc) {
    if (!kichThuoc || typeof kichThuoc !== 'string') {
        return { cao: null, ngang: null };
    }

    const cleaned = kichThuoc.trim().toLowerCase();

    const patternNgangCaoCompact = /ngang\s*(\d+)\s*m\s*(\d+)?\s*x\s*cao\s*(\d+)\s*m\s*(\d+)?/i;
    const matchNgangCaoCompact = cleaned.match(patternNgangCaoCompact);

    if (matchNgangCaoCompact) {
        let ngang = parseFloat(matchNgangCaoCompact[1]);
        if (matchNgangCaoCompact[2]) {
            ngang = ngang + parseFloat('0.' + matchNgangCaoCompact[2]);
        }
        ngang = ngang * 100;

        let cao = parseFloat(matchNgangCaoCompact[3]);
        if (matchNgangCaoCompact[4]) {
            cao = cao + parseFloat('0.' + matchNgangCaoCompact[4]);
        }
        cao = cao * 100;

        return {
            cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''),
            ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '')
        };
    }

    const patternNgangCao = /ngang\s*(\d+(?:\.\d+)?)\s*(?:m|cm)?\s*(?:(\d+))?\s*x\s*cao\s*(\d+(?:\.\d+)?)\s*(?:m|cm)?/i;
    const matchNgangCao = cleaned.match(patternNgangCao);

    if (matchNgangCao) {
        let ngang = parseFloat(matchNgangCao[1]);
        if (matchNgangCao[2]) {
            ngang = ngang + parseFloat('0.' + matchNgangCao[2]);
        }
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            ngang = ngang * 100;
        }

        let cao = parseFloat(matchNgangCao[3]);
        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            cao = cao * 100;
        }

        return {
            cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''),
            ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '')
        };
    }

    const patternShort = /(\d+)\s*m\s*(\d+)?\s*x\s*(\d+)\s*m/i;
    const matchShort = cleaned.match(patternShort);

    if (matchShort) {
        let ngang = parseFloat(matchShort[1]);
        if (matchShort[2]) {
            ngang = ngang + parseFloat('0.' + matchShort[2]);
        }
        ngang = ngang * 100;

        let cao = parseFloat(matchShort[3]) * 100;

        return {
            cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''),
            ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '')
        };
    }

    const pattern1 = /(\d+(?:\.\d+)?)\s*(?:cm|m)?\s*x\s*(\d+(?:\.\d+)?)\s*(?:cm|m)?/i;
    const match1 = cleaned.match(pattern1);

    if (match1) {
        let cao = parseFloat(match1[1]);
        let ngang = parseFloat(match1[2]);

        if (cleaned.includes('m') && !cleaned.includes('cm')) {
            cao = cao * 100;
            ngang = ngang * 100;
        }

        return {
            cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''),
            ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '')
        };
    }

    const pattern2 = /(\d+(?:\.\d+)?)\s*x\s*(\d+(?:\.\d+)?)/i;
    const match2 = cleaned.match(pattern2);

    if (match2) {
        const cao = parseFloat(match2[1]);
        const ngang = parseFloat(match2[2]);
        return {
            cao: Number.isInteger(cao) ? cao.toString() : cao.toFixed(1).replace(/\.0$/, ''),
            ngang: Number.isInteger(ngang) ? ngang.toString() : ngang.toFixed(1).replace(/\.0$/, '')
        };
    }

    return { cao: null, ngang: null };
}

async function getActiveTemplate() {
    let template = await Template.findOne({ isActive: true });
    if (!template) template = await Template.findOne().sort({ createdAt: -1 });
    return template || null;
}

async function getExportConfig() {
    const template = await getActiveTemplate();
    const rawSkuNhapKho = String(template?.skuNhapKhoSuffix || '').trim();
    const fix = (v) => {
        const s = String(v ?? '');
        if (!/[ÃÂÄÆ]/.test(s)) return s;
        try {
            const fixed = Buffer.from(s, 'latin1').toString('utf8');
            return /[ÃÂÄÆ]/.test(fixed) ? s : fixed;
        } catch {
            return s;
        }
    };
    return {
        template,
        warehousePhoiName: fix(template?.warehousePhoiName || 'Kho Phôi - Shi'),
        warehouseNVLName: fix(template?.warehouseNVLName || 'Kho NVL - Shi'),
        warehousePhePhamName: fix(template?.warehousePhePhamName || 'Kho Phế phẩm - Shi'),
        skuHangLoiSuffix: template?.skuHangLoiSuffix || '00-404-230',
        // Nghiệp vụ: SKU nhập lại kho luôn {maMau}-00-000-230.
        skuNhapKhoSuffix:
            !rawSkuNhapKho || rawSkuNhapKho === '00-403-230' || rawSkuNhapKho === '00-404-230'
                ? '00-000-230'
                : rawSkuNhapKho,
        csvHeader: Array.isArray(template?.csvHeader) ? template.csvHeader.map(fix) : [],
        startRow: Number(template?.startRow) > 0 ? Number(template.startRow) : 1,
        filePath: template?.filePath || null
    };
}

function csvEscape(cell) {
    if (cell === null || cell === undefined) return '';
    const s = String(cell);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
}

function formatDecimalComma(value) {
    // Chỉ chuyển dấu thập phân cho các giá trị số/chuỗi số, tránh đụng vào SKU/text
    if (value === null || value === undefined || value === '') return value;
    if (typeof value === 'number' && Number.isFinite(value)) {
        return String(value).replace('.', ',');
    }
    const s = String(value).trim();
    // 12.3 -> 12,3 ; 12.00 -> 12,00
    if (/^-?\d+\.\d+$/.test(s)) return s.replace('.', ',');
    return value;
}

/** Một dòng CSV: cột A–X (24 cột), chỉ gán D,E,N,O,Q,R,S,X theo yêu cầu nhập kho.
 * Mặc định: O luôn copy từ N nếu không truyền riêng.
 */
function buildCsvLine24({ d, e, n, o, q, r, s = 1, x = 1 }) {
    const row = new Array(24).fill('');
    const qtyN = n === '' || n === undefined || n === null ? '' : formatDecimalComma(n);
    const qtyO =
        o === undefined
            ? qtyN
            : o === '' || o === null
            ? ''
            : formatDecimalComma(o);

    row[3] = d;
    row[4] = e;
    row[13] = qtyN;
    row[14] = qtyO;
    row[16] = q;
    row[17] = r;
    row[18] = String(formatDecimalComma(s));
    row[23] = String(formatDecimalComma(x));
    return row.map(csvEscape).join(',');
}

function buildDefaultCsvHeader24() {
    // Fallback tối thiểu: A..X
    const letters = Array.from({ length: 24 }, (_, i) => String.fromCharCode('A'.charCodeAt(0) + i));
    return letters;
}

function buildCsvHeaderLine24(headerCells) {
    const header = Array.isArray(headerCells) && headerCells.length ? headerCells : buildDefaultCsvHeader24();
    const normalized = header.length >= 24 ? header.slice(0, 24) : [...header, ...buildDefaultCsvHeader24().slice(header.length)];
    return normalized.map(csvEscape).join(',');
}

function sheetSet(worksheet, cell, value) {
    XLSX.utils.sheet_add_aoa(worksheet, [[value]], { origin: cell });
}

function rowNumberToExcelRow(n) {
    return Number(n) || 1;
}

function writeRowsToExcelTemplate({ templatePath, startRow, rows }) {
    const workbook = XLSX.readFile(templatePath);
    const sheetName = workbook.SheetNames[0];
    if (!sheetName) throw new Error('Template Excel không có sheet');
    const worksheet = workbook.Sheets[sheetName];

    // startRow trong DB/UI là dòng BẮT ĐẦU GHI DATA (1-indexed)
    const dataStartRow = rowNumberToExcelRow(startRow);

    rows.forEach((r, idx) => {
        const excelRow = dataStartRow + idx;
        // D,E,N,O,Q,R,S,X
        sheetSet(worksheet, `D${excelRow}`, r.D);
        sheetSet(worksheet, `E${excelRow}`, r.E);
        sheetSet(worksheet, `N${excelRow}`, r.N);
        sheetSet(worksheet, `O${excelRow}`, r.O);
        sheetSet(worksheet, `Q${excelRow}`, r.Q);
        sheetSet(worksheet, `R${excelRow}`, r.R);
        sheetSet(worksheet, `S${excelRow}`, r.S);
        sheetSet(worksheet, `X${excelRow}`, r.X);
    });

    return XLSX.write(workbook, { bookType: 'xlsx', type: 'buffer' });
}

function readTemplateCsvPrefixLines(templateCsvPath, startRow) {
    const raw = fs.readFileSync(templateCsvPath, 'utf8');
    const lines = raw.split(/\r\n|\n|\r/);
    const prefixLineCount = Math.max(0, rowNumberToExcelRow(startRow) - 1);
    return lines.slice(0, prefixLineCount);
}

/**
 * Tra SKU MasterDataVai (cùng logic bản xlsx cũ).
 * @returns {Promise<{ sku: string, slLoi: number }>}
 */
async function resolveSkuForNhapItem(item) {
    const slLoi = item.slLoi !== undefined && item.slLoi !== null ? Number(item.slLoi) || 0 : 0;
    let sku = item.szSku || '';
    const maMau = item.maMau;

    if (!maMau) {
        return { sku: sku || '', slLoi };
    }

    const isVaiThua =
        item.kichThuoc &&
        (item.kichThuoc.includes('Vải thừa') ||
            item.kichThuoc.includes('vải thừa') ||
            item.kichThuoc.includes('Vải phát sinh') ||
            item.kichThuoc.includes('vải phát sinh'));

    const szSkuParts = item.szSku ? item.szSku.split('-') : [];
    const isVaiThuaFormat =
        szSkuParts.length === 4 &&
        /^\d+$/.test(szSkuParts[0]) &&
        /^\d+$/.test(szSkuParts[1]) &&
        /^\d+$/.test(szSkuParts[2]) &&
        /^\d+$/.test(szSkuParts[3]);

    if (isVaiThua || isVaiThuaFormat) {
        return { sku: item.szSku, slLoi };
    }

    const mauVaiData = await MauVai.findOne({ maMau: maMau });
    const tenMau = mauVaiData ? mauVaiData.tenMau : null;

    let cao = null;
    let ngang = null;
    let kichThuocData = null;

    if (item.szSku) {
        kichThuocData = await KichThuoc.findOne({ szSku: item.szSku });

        if (kichThuocData && kichThuocData.kichThuoc) {
            const parsed = parseCaoNgangFromKichThuoc(kichThuocData.kichThuoc);
            cao = parsed.cao;
            ngang = parsed.ngang;
        } else {
            const parts = item.szSku.split('-');
            if (parts.length >= 4) {
                ngang = parts[parts.length - 2];
                cao = parts[parts.length - 1];
            }
        }

        if (cao && ngang) {
            const tenMauNormalized = tenMau ? String(tenMau || '').trim() : String(maMau || '').trim();
            const caoNormalized = String(cao || '')
                .trim()
                .replace(/\.0+$/, '');
            const ngangNormalized = String(ngang || '')
                .trim()
                .replace(/\.0+$/, '');

            let masterData = null;

            masterData = await MasterDataVai.findOne({
                mau: tenMauNormalized,
                cao: caoNormalized,
                ngang: ngangNormalized
            });

            if (!masterData) {
                masterData = await MasterDataVai.findOne({
                    mau: {
                        $regex: new RegExp(
                            `^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
                            'i'
                        )
                    },
                    cao: caoNormalized,
                    ngang: ngangNormalized
                });
            }

            if (!masterData) {
                masterData = await MasterDataVai.findOne({
                    mau: {
                        $regex: new RegExp(
                            `^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
                            'i'
                        )
                    },
                    cao: ngangNormalized,
                    ngang: caoNormalized
                });
            }

            if (!masterData) {
                const caoInt = Math.round(parseFloat(caoNormalized)).toString();
                const ngangInt = Math.round(parseFloat(ngangNormalized)).toString();
                masterData = await MasterDataVai.findOne({
                    mau: {
                        $regex: new RegExp(
                            `^${tenMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
                            'i'
                        )
                    },
                    $or: [
                        { cao: caoInt, ngang: ngangInt },
                        { cao: caoNormalized, ngang: ngangNormalized },
                        { cao: ngangInt, ngang: caoInt }
                    ]
                });
            }

            if (!masterData && tenMau) {
                const maMauNormalized = String(maMau || '').trim();
                masterData = await MasterDataVai.findOne({
                    mau: {
                        $regex: new RegExp(
                            `^${maMauNormalized.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`,
                            'i'
                        )
                    },
                    cao: caoNormalized,
                    ngang: ngangNormalized
                });
            }

            if (masterData && masterData.sku) {
                sku = masterData.sku;
            } else {
                sku = '';
            }
        }
    }

    if (sku && sku !== item.szSku) {
        return { sku, slLoi };
    }
    if (!sku || sku === '') {
        return { sku: `[LỖI: Không tìm thấy SKU cho ${item.maMau}]`, slLoi };
    }
    return { sku: item.szSku, slLoi };
}

function skuHangLoiFromMaMau(maMau, suffix) {
    return `${String(maMau).trim()}-${suffix}`;
}

function appendCayVaiExtraRows(lines, cayVaiList, cfg) {
    if (!Array.isArray(cayVaiList)) return;
    for (const cv of cayVaiList) {
        const maMau = cv.maMau;
        if (!maMau) continue;
        const vaiLoiSoM = cv.vaiLoi && Number(cv.vaiLoi.soM) > 0 ? Number(cv.vaiLoi.soM) : 0;
        const nhapSoM = cv.nhapLaiKho && Number(cv.nhapLaiKho.soM) > 0 ? Number(cv.nhapLaiKho.soM) : 0;

        if (vaiLoiSoM > 0) {
            lines.push(
                buildCsvLine24({
                    d: cfg.warehousePhePhamName,
                    e: skuHangLoiFromMaMau(maMau, cfg.skuHangLoiSuffix),
                    n: vaiLoiSoM,
                    q: 'Meter',
                    r: 'Meter',
                    s: 1,
                    x: 1
                })
            );
        }
        if (nhapSoM > 0) {
            lines.push(
                buildCsvLine24({
                    d: cfg.warehouseNVLName,
                    e: skuHangLoiFromMaMau(maMau, cfg.skuNhapKhoSuffix),
                    n: nhapSoM,
                    q: 'Meter',
                    r: 'Meter',
                    s: 1,
                    x: 1
                })
            );
        }
    }
}

// GET — xuất CSV từ DB (quản lý: toàn bộ; nhân viên: của mình)
router.get('/', requireLogin, requireWarehouseAccess, async (req, res) => {
    try {
        const role = req.session.user.role;
        const username = req.session.user.username;
        const isWide = role === 'warehouse_manager' || role === 'admin';
        const userFilter = isWide ? {} : { createdBy: username };

        const cfg = await getExportConfig();
        const nhapPhoiList = await NhapPhoi.find(userFilter).sort({ importDate: 1, createdAt: 1 });

        const catIds = [...new Set(nhapPhoiList.map((r) => r.catVaiId).filter(Boolean))];
        const extraCay = [];
        for (const catId of catIds) {
            const dt = await DoiTuongCatVai.findOne({ catVaiId: catId });
            if (!dt) continue;
            extraCay.push({ maMau: dt.maMau, vaiLoi: dt.vaiLoi, nhapLaiKho: dt.nhapLaiKho });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const tplPath = cfg.filePath && fs.existsSync(cfg.filePath) ? cfg.filePath : null;
        const ext = String(path.extname(cfg?.template?.filename || tplPath || '') || '').toLowerCase();

        // Nếu template active là Excel => xuất XLSX để giữ nguyên header/format trong template
        if (tplPath && (ext === '.xlsx' || ext === '.xls')) {
            const excelRows = [];

            for (const rec of nhapPhoiList) {
                const item = {
                    maMau: rec.maMau,
                    szSku: rec.szSku,
                    kichThuoc: rec.kichThuoc,
                    soLuong: rec.soLuong,
                    slLoi: rec.slLoi !== undefined && rec.slLoi !== null ? rec.slLoi : 0
                };
                const { sku } = await resolveSkuForNhapItem(item);
                excelRows.push({
                    D: cfg.warehousePhoiName,
                    E: sku,
                    N: rec.soLuong,
                    O: rec.soLuong,
                    Q: 'Unit',
                    R: 'Unit',
                    S: 1,
                    X: 1
                });
            }

            for (const cv of extraCay) {
                const maMau = cv.maMau;
                if (!maMau) continue;
                const vaiLoiSoM = cv.vaiLoi && Number(cv.vaiLoi.soM) > 0 ? Number(cv.vaiLoi.soM) : 0;
                const nhapSoM = cv.nhapLaiKho && Number(cv.nhapLaiKho.soM) > 0 ? Number(cv.nhapLaiKho.soM) : 0;
                if (vaiLoiSoM > 0) {
                    excelRows.push({
                        D: cfg.warehousePhePhamName,
                        E: skuHangLoiFromMaMau(maMau, cfg.skuHangLoiSuffix),
                        N: vaiLoiSoM,
                        O: vaiLoiSoM,
                        Q: 'Meter',
                        R: 'Meter',
                        S: 1,
                        X: 1
                    });
                }
                if (nhapSoM > 0) {
                    excelRows.push({
                        D: cfg.warehouseNVLName,
                        E: skuHangLoiFromMaMau(maMau, cfg.skuNhapKhoSuffix),
                        N: nhapSoM,
                        O: nhapSoM,
                        Q: 'Meter',
                        R: 'Meter',
                        S: 1,
                        X: 1
                    });
                }
            }

            const buffer = writeRowsToExcelTemplate({
                templatePath: tplPath,
                startRow: cfg.startRow,
                rows: excelRows
            });
            const filename = `NhapPhoi_Export_${timestamp}.xlsx`;
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            return res.send(buffer);
        }

        // Template CSV: giữ nguyên header/prefix trong file template, rồi append data
        if (tplPath && ext === '.csv') {
            const lines = readTemplateCsvPrefixLines(tplPath, cfg.startRow);

            for (const rec of nhapPhoiList) {
                const item = {
                    maMau: rec.maMau,
                    szSku: rec.szSku,
                    kichThuoc: rec.kichThuoc,
                    soLuong: rec.soLuong,
                    slLoi: rec.slLoi !== undefined && rec.slLoi !== null ? rec.slLoi : 0
                };
                const { sku } = await resolveSkuForNhapItem(item);
                lines.push(
                    buildCsvLine24({
                        d: cfg.warehousePhoiName,
                        e: sku,
                        n: rec.soLuong,
                        q: 'Unit',
                        r: 'Unit',
                        s: 1,
                        x: 1
                    })
                );
            }

            appendCayVaiExtraRows(lines, extraCay, cfg);

            const csvBody = lines.join('\r\n');
            const filename = `NhapPhoi_Export_${timestamp}.csv`;
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            return res.send('\ufeff' + csvBody);
        }

        // Không có template CSV file => xuất CSV theo header đã lưu trong template active
        const lines = [];
        for (let i = 1; i < (cfg.startRow || 1); i++) lines.push('');
        lines.push(buildCsvHeaderLine24(cfg.csvHeader));

        for (const rec of nhapPhoiList) {
            const item = {
                maMau: rec.maMau,
                szSku: rec.szSku,
                kichThuoc: rec.kichThuoc,
                soLuong: rec.soLuong,
                slLoi: rec.slLoi !== undefined && rec.slLoi !== null ? rec.slLoi : 0
            };
            const { sku } = await resolveSkuForNhapItem(item);
            lines.push(
                buildCsvLine24({
                    d: cfg.warehousePhoiName,
                    e: sku,
                    n: rec.soLuong,
                    q: 'Unit',
                    r: 'Unit',
                    s: 1,
                    x: 1
                })
            );
        }

        appendCayVaiExtraRows(lines, extraCay, cfg);

        const csvBody = lines.join('\r\n');
        const filename = `NhapPhoi_Export_${timestamp}.csv`;
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        return res.send('\ufeff' + csvBody);
    } catch (error) {
        console.error('Error GET export nhap phoi:', error);
        res.status(500).json({ success: false, message: 'Lỗi xuất file nhập phôi.', error: error.message });
    }
});

// POST — xuất CSV từ payload (nhân viên kho)
router.post('/', requireLogin, requireWarehouseAccess, async (req, res) => {
    const { items, cayVaiList } = req.body;

    if (!items || !Array.isArray(items)) {
        return res.status(400).json({ success: false, message: 'Invalid data format.' });
    }

    try {
        const cfg = await getExportConfig();
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const tplPath = cfg.filePath && fs.existsSync(cfg.filePath) ? cfg.filePath : null;
        const ext = String(path.extname(cfg?.template?.filename || tplPath || '') || '').toLowerCase();

        // Template Excel active => xuất XLSX để giữ header/format
        if (tplPath && (ext === '.xlsx' || ext === '.xls')) {
            const excelRows = [];

            for (const item of items) {
                const { sku } = await resolveSkuForNhapItem(item);
                const qty = item.soLuong ?? 0;
                excelRows.push({
                    D: cfg.warehousePhoiName,
                    E: sku,
                    N: qty,
                    O: qty,
                    Q: 'Unit',
                    R: 'Unit',
                    S: 1,
                    X: 1
                });
            }

            if (Array.isArray(cayVaiList)) {
                for (const cv of cayVaiList) {
                    const maMau = cv.maMau;
                    if (!maMau) continue;
                    const vaiLoiSoM = cv.vaiLoi && Number(cv.vaiLoi.soM) > 0 ? Number(cv.vaiLoi.soM) : 0;
                    const nhapSoM = cv.nhapLaiKho && Number(cv.nhapLaiKho.soM) > 0 ? Number(cv.nhapLaiKho.soM) : 0;
                    if (vaiLoiSoM > 0) {
                        excelRows.push({
                            D: cfg.warehousePhePhamName,
                            E: skuHangLoiFromMaMau(maMau, cfg.skuHangLoiSuffix),
                            N: vaiLoiSoM,
                            O: vaiLoiSoM,
                            Q: 'Meter',
                            R: 'Meter',
                            S: 1,
                            X: 1
                        });
                    }
                    if (nhapSoM > 0) {
                        excelRows.push({
                            D: cfg.warehouseNVLName,
                            E: skuHangLoiFromMaMau(maMau, cfg.skuNhapKhoSuffix),
                            N: nhapSoM,
                            O: nhapSoM,
                            Q: 'Meter',
                            R: 'Meter',
                            S: 1,
                            X: 1
                        });
                    }
                }
            }

            const buffer = writeRowsToExcelTemplate({
                templatePath: tplPath,
                startRow: cfg.startRow,
                rows: excelRows
            });
            const filename = `NhapPhoi_Export_${timestamp}.xlsx`;
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            return res.send(buffer);
        }

        // CSV template active: giữ nguyên header/prefix trong file template, rồi append data
        if (tplPath && ext === '.csv') {
            const lines = readTemplateCsvPrefixLines(tplPath, cfg.startRow);

            for (const item of items) {
                const { sku } = await resolveSkuForNhapItem(item);
                lines.push(
                    buildCsvLine24({
                        d: cfg.warehousePhoiName,
                        e: sku,
                        n: item.soLuong ?? 0,
                        q: 'Unit',
                        r: 'Unit',
                        s: 1,
                        x: 1
                    })
                );
            }
            appendCayVaiExtraRows(lines, cayVaiList, cfg);

            const csvBody = lines.join('\r\n');
            const filename = `NhapPhoi_Export_${timestamp}.csv`;
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Type', 'text/csv; charset=utf-8');
            return res.send('\ufeff' + csvBody);
        }

        // CSV output (fallback header theo template active)
        const lines = [];
        for (let i = 1; i < (cfg.startRow || 1); i++) lines.push('');
        lines.push(buildCsvHeaderLine24(cfg.csvHeader));

        for (const item of items) {
            const { sku } = await resolveSkuForNhapItem(item);
            lines.push(
                buildCsvLine24({
                    d: cfg.warehousePhoiName,
                    e: sku,
                    n: item.soLuong ?? 0,
                    q: 'Unit',
                    r: 'Unit',
                    s: 1,
                    x: 1
                })
            );
        }
        appendCayVaiExtraRows(lines, cayVaiList, cfg);

        const csvBody = lines.join('\r\n');
        const filename = `NhapPhoi_Export_${timestamp}.csv`;
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        return res.send('\ufeff' + csvBody);
    } catch (error) {
        console.error('Error exporting nhap phoi CSV:', error);
        res.status(500).json({ success: false, message: 'Failed to export data.', error: error.message });
    }
});

module.exports = router;
