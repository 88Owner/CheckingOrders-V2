/**
 * Bung combo lồng nhau ra SKU base (leaf).
 * - Đơn có maHang = combo cha (vd. 50-26-200-72-N3) → expand đệ quy.
 * - Quét mã combo trên dòng đơn → chặn, hướng dẫn quét thành phần.
 * - Quét mã combo con (vd. CH3-CH-000-001, không có dòng đơn riêng) → 1 lần quét = đủ SL base tương ứng.
 */
const comboCache = require('./comboCache');

const MAX_COMBO_DEPTH = 12;

async function getCombosByCode(code) {
    const trimmed = String(code || '').trim();
    if (!trimmed) return [];
    return comboCache.getCombosByCode(trimmed);
}

async function isComboSku(code) {
    const combos = await getCombosByCode(code);
    return combos.length > 0;
}

/**
 * @param {string} skuCode
 * @param {number} multiplier - số lượng dòng đơn hoặc 1 mỗi lần quét
 * @param {Set<string>} [visited]
 * @returns {Promise<Map<string, number>>} base SKU -> tổng SL
 */
async function expandLineSku(skuCode, multiplier, visited = new Set()) {
    const code = String(skuCode || '').trim();
    const mult = Number(multiplier) || 0;
    const result = new Map();
    if (!code || mult <= 0) return result;

    const combos = await getCombosByCode(code);
    if (!combos.length) {
        result.set(code, (result.get(code) || 0) + mult);
        return result;
    }

    if (visited.has(code) || visited.size >= MAX_COMBO_DEPTH) {
        result.set(code, (result.get(code) || 0) + mult);
        return result;
    }
    visited.add(code);

    for (const item of combos) {
        const childCode = String(item.maHang || '').trim();
        const itemQty = Number(item.soLuong) || 0;
        if (!childCode || itemQty <= 0) continue;
        const childExpanded = await expandLineSku(childCode, mult * itemQty, visited);
        for (const [base, qty] of childExpanded) {
            result.set(base, (result.get(base) || 0) + qty);
        }
    }
    visited.delete(code);
    return result;
}

/** Gộp yêu cầu theo SKU base từ tất cả dòng Order trong một maVanDon */
async function buildVanDonBaseRequirements(orders) {
    const req = new Map();
    for (const o of orders || []) {
        const expanded = await expandLineSku(o.maHang, o.soLuong);
        for (const [base, qty] of expanded) {
            req.set(base, (req.get(base) || 0) + qty);
        }
    }
    return req;
}

/** SL cộng vào tiến độ khi quét một lần mã scannedCode */
async function getScanCredit(scannedCode) {
    return expandLineSku(scannedCode, 1);
}

async function formatExpandedBasesHint(skuCode) {
    const expanded = await expandLineSku(skuCode, 1);
    return [...expanded.entries()].map(([base, qty]) => `${base} (x${qty})`).join(', ');
}

/** Các dòng đơn là combo (maHang = comboCode) có đóng góp vào baseMaHang */
async function findComboOrdersContributingToBase(orders, baseMaHang) {
    const base = String(baseMaHang || '').trim();
    const results = [];
    for (const order of orders || []) {
        const combos = await getCombosByCode(order.maHang);
        if (!combos.length) continue;
        const expanded = await expandLineSku(order.maHang, order.soLuong);
        const contribution = expanded.get(base) || 0;
        if (contribution > 0) {
            results.push({
                order,
                contribution,
                comboCode: String(order.maHang).trim()
            });
        }
    }
    return results;
}

/**
 * Chuẩn bị ngữ cảnh quét cho một maVanDon + mã quét.
 * @param {import('mongoose').Model} Order
 */
async function resolveScanForVanDon(maVanDon, scannedCode, Order) {
    const code = String(scannedCode || '').trim();
    const allOrders = await Order.find({ maVanDon });
    const baseRequirements = await buildVanDonBaseRequirements(allOrders);

    const comboOnOrder = await isComboSku(code) &&
        allOrders.some((o) => String(o.maHang).trim() === code);

    if (comboOnOrder) {
        const hint = await formatExpandedBasesHint(code);
        return {
            ok: false,
            message: `Đây là mã combo trên đơn (${code}). Vui lòng quét mã hàng: ${hint}`
        };
    }

    const scanCredit = await getScanCredit(code);
    if (scanCredit.size === 0) {
        return { ok: false, message: 'Không tìm thấy mã hàng trong đơn vận đơn này' };
    }

    let primaryBase = null;
    let creditQty = 0;
    for (const [base, credit] of scanCredit) {
        const required = baseRequirements.get(base) || 0;
        if (required <= 0) continue;
        if (!primaryBase || required >= (baseRequirements.get(primaryBase) || 0)) {
            primaryBase = base;
            creditQty = credit;
        }
    }

    if (!primaryBase) {
        primaryBase = [...scanCredit.keys()][0];
        creditQty = scanCredit.get(primaryBase) || 0;
    }

    const totalRequiredQuantity = baseRequirements.get(primaryBase) || 0;
    if (totalRequiredQuantity <= 0) {
        return { ok: false, message: 'Không tìm thấy mã hàng trong đơn vận đơn này' };
    }

    const directOrders = allOrders.filter((o) => String(o.maHang).trim() === primaryBase);
    const comboContributions = await findComboOrdersContributingToBase(allOrders, primaryBase);

    let mainOrder = directOrders.length > 0 ? directOrders[0] : null;
    let isComboOrder = false;
    if (!mainOrder && comboContributions.length > 0) {
        mainOrder = comboContributions[0].order;
        isComboOrder = true;
    }

    if (!mainOrder) {
        return { ok: false, message: 'Không tìm thấy mã hàng trong đơn vận đơn này' };
    }

    const comboOrders = comboContributions.map((c) => ({
        order: c.order,
        combo: {
            comboCode: c.comboCode,
            maHang: primaryBase,
            soLuong: c.contribution
        }
    }));

    return {
        ok: true,
        scannedCode: code,
        primaryBase,
        creditQty,
        scanCredit: Object.fromEntries(scanCredit),
        directOrders,
        directOrder: directOrders[0] || null,
        comboOrders,
        mainOrder,
        isComboOrder,
        totalRequiredQuantity,
        totalScannedQuantity: mainOrder.scannedQuantity || 0,
        baseRequirements: Object.fromEntries(baseRequirements)
    };
}

module.exports = {
    expandLineSku,
    buildVanDonBaseRequirements,
    getScanCredit,
    formatExpandedBasesHint,
    findComboOrdersContributingToBase,
    resolveScanForVanDon,
    isComboSku,
    getCombosByCode
};
