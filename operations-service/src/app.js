const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const XLSX = require('xlsx');
const bwipjs = require('bwip-js');
const { pool } = require('./db');
const config = require('./config');

const app = express();
const OPERATIONS_ROLES = new Set([
  'production_worker',
  'production_manager',
  'qa',
  'fabric_cutting_team',
  'cotton_press_team',
  'eyelet_team',
  'sewing_team',
  'assembly_team'
]);

function readCookie(req, key) {
  const cookieHeader = req.headers.cookie || '';
  const parts = cookieHeader.split(';').map((item) => item.trim());
  const found = parts.find((item) => item.startsWith(`${key}=`));
  return found ? decodeURIComponent(found.substring(key.length + 1)) : null;
}

function getAuthUser(req) {
  const token = readCookie(req, 'ops_auth');
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, config.sharedAuthSecret);
    if (!decoded?.role || !OPERATIONS_ROLES.has(decoded.role)) {
      return null;
    }
    return decoded;
  } catch (_error) {
    return null;
  }
}

function requireOpsAuth(req, res, next) {
  const authUser = getAuthUser(req);
  if (!authUser) {
    return res.status(401).json({
      ok: false,
      message: 'Unauthorized. Please login from main app.'
    });
  }
  req.authUser = authUser;
  next();
}

function requireRole(expectedRole) {
  return (req, res, next) => {
    const authUser = getAuthUser(req);
    if (!authUser) {
      return res.status(401).json({
        ok: false,
        message: 'Unauthorized. Please login from main app.'
      });
    }
    if (authUser.role !== expectedRole) {
      return res.status(403).json({ ok: false, message: 'Forbidden' });
    }
    req.authUser = authUser;
    next();
  };
}

async function lookupProductNameBySkuFromMainApp(sku, token) {
  const base = String(config.mainAppUrl || 'http://localhost:3001').replace(/\/+$/, '');
  const url = `${base}/api/master-data/sku/${encodeURIComponent(sku)}`;
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  let data = null;
  try {
    data = await response.json();
  } catch (_error) {
    data = null;
  }

  if (!response.ok || !data?.success || !data?.data?.productName) {
    return null;
  }
  return String(data.data.productName).trim() || null;
}

const qaImportUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }
});

function normalizeHeader(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function parseQaRowsFromWorkbook(buffer) {
  const workbook = XLSX.read(buffer, { type: 'buffer' });
  const firstSheet = workbook.SheetNames[0];
  if (!firstSheet) {
    throw new Error('File import không có sheet dữ liệu');
  }

  const rows = XLSX.utils.sheet_to_json(workbook.Sheets[firstSheet], { defval: '' });
  if (!rows.length) {
    return [];
  }

  const headerMap = {};
  Object.keys(rows[0]).forEach((key) => {
    headerMap[normalizeHeader(key)] = key;
  });

  const orderCodeKey =
    headerMap['ma don'] || headerMap['madon'] || headerMap['order code'] || headerMap['ordercode'];
  const skuKey = headerMap['sku'];
  const productNameKey =
    headerMap['ten sp'] ||
    headerMap['ten san pham'] ||
    headerMap['tensp'] ||
    headerMap['product name'] ||
    headerMap['productname'];
  const quantityKey = headerMap['so luong'] || headerMap['soluong'] || headerMap['quantity'];

  if (!orderCodeKey || !skuKey || !productNameKey || !quantityKey) {
    throw new Error('File phải có đủ 4 cột: Mã đơn, SKU, Tên SP, Số lượng');
  }

  return rows
    .map((row) => {
      const orderCode = String(row[orderCodeKey] || '').trim();
      const sku = String(row[skuKey] || '').trim();
      const productName = String(row[productNameKey] || '').trim();
      const quantityRaw = Number(row[quantityKey]);
      const quantity = Number.isFinite(quantityRaw) ? Math.floor(quantityRaw) : NaN;
      return { orderCode, sku, productName, quantity };
    })
    .filter((item) => item.orderCode && item.sku && Number.isInteger(item.quantity) && item.quantity > 0);
}

app.use(express.json());
app.use(express.static('public'));

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'operations-service',
    message: 'Service is running',
    endpoints: {
      health: '/health',
      orders: '/api/operations/orders',
      actions: '/api/operations/actions'
    }
  });
});

app.get('/auth/sso', (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).send('Missing token');
  }

  try {
    const decoded = jwt.verify(String(token), config.sharedAuthSecret);
    if (!decoded?.role || !OPERATIONS_ROLES.has(decoded.role)) {
      return res.status(403).send('Role is not allowed for operations service');
    }

    res.cookie('ops_auth', String(token), {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      maxAge: 24 * 60 * 60 * 1000
    });
    return res.redirect('/app');
  } catch (_error) {
    return res.status(401).send('Invalid token');
  }
});

app.get('/app', (req, res) => {
  const authUser = getAuthUser(req);
  if (!authUser) {
    return res.redirect(`${config.mainAppUrl}/login`);
  }

  const rolePathMap = {
    production_worker: '/roles/production-worker',
    production_manager: '/roles/production-manager',
    qa: '/roles/qa',
    fabric_cutting_team: '/roles/fabric-cutting-team',
    cotton_press_team: '/roles/cotton-press-team',
    eyelet_team: '/roles/eyelet-team',
    sewing_team: '/roles/sewing-team',
    assembly_team: '/roles/assembly-team'
  };

  const target = rolePathMap[authUser.role] || '/roles/production-worker';
  return res.redirect(target);
});

app.get('/api/me', requireOpsAuth, (req, res) => {
  res.json({
    ok: true,
    user: {
      username: req.authUser.username || 'unknown',
      role: req.authUser.role
    }
  });
});

app.get('/api/qa/orders', requireRole('qa'), async (_req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, order_code, sku, product_name, quantity, created_by, created_at, updated_at
      FROM qa_orders
      ORDER BY created_at DESC
      LIMIT 1000
      `
    );
    res.json({ ok: true, items: result.rows });
  } catch (error) {
    res.status(500).json({ ok: false, message: error.message });
  }
});

app.get('/api/qa/masterdata-by-sku/:sku', requireRole('qa'), async (req, res) => {
  try {
    const sku = String(req.params.sku || '').trim();
    if (!sku) {
      return res.status(400).json({ ok: false, message: 'SKU không hợp lệ' });
    }

    const token = readCookie(req, 'ops_auth');
    if (!token) {
      return res.status(401).json({ ok: false, message: 'Unauthorized' });
    }

    const productName = await lookupProductNameBySkuFromMainApp(sku, token);
    if (!productName) {
      return res.status(404).json({ ok: false, message: 'Không tìm thấy tên sản phẩm theo SKU' });
    }

    return res.json({ ok: true, data: { sku, productName } });
  } catch (error) {
    return res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/qa/orders', requireRole('qa'), async (req, res) => {
  const { orderCode, sku, productName, quantity } = req.body;
  if (!orderCode || !sku || !productName || !quantity) {
    return res.status(400).json({ ok: false, message: 'Thiếu dữ liệu bắt buộc' });
  }

  const qty = Number(quantity);
  if (!Number.isFinite(qty) || qty <= 0) {
    return res.status(400).json({ ok: false, message: 'Số lượng không hợp lệ' });
  }

  try {
    const result = await pool.query(
      `
      INSERT INTO qa_orders (order_code, sku, product_name, quantity, created_by)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (order_code)
      DO UPDATE SET
        sku = EXCLUDED.sku,
        product_name = EXCLUDED.product_name,
        quantity = EXCLUDED.quantity,
        updated_at = NOW()
      RETURNING id, order_code, sku, product_name, quantity, created_by, created_at, updated_at
      `,
      [
        String(orderCode).trim(),
        String(sku).trim(),
        String(productName).trim(),
        Math.floor(qty),
        req.authUser?.username || null
      ]
    );

    res.json({ ok: true, item: result.rows[0] });
  } catch (error) {
    res.status(500).json({ ok: false, message: error.message });
  }
});

app.post('/api/qa/orders/import', requireRole('qa'), qaImportUpload.single('xlsxFile'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ ok: false, message: 'Vui lòng chọn file Excel để import' });
  }

  try {
    const rows = parseQaRowsFromWorkbook(req.file.buffer);
    if (!rows.length) {
      return res.status(400).json({ ok: false, message: 'Không có dòng hợp lệ để import' });
    }

    let inserted = 0;
    let updated = 0;
    let autoFilled = 0;
    let missingProductName = 0;
    const token = readCookie(req, 'ops_auth');

    for (const row of rows) {
      let finalProductName = String(row.productName || '').trim();
      if (!finalProductName && token) {
        const lookedUpName = await lookupProductNameBySkuFromMainApp(row.sku, token);
        if (lookedUpName) {
          finalProductName = lookedUpName;
          autoFilled += 1;
        }
      }

      if (!finalProductName) {
        missingProductName += 1;
        continue;
      }

      const result = await pool.query(
        `
        INSERT INTO qa_orders (order_code, sku, product_name, quantity, created_by)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (order_code)
        DO UPDATE SET
          sku = EXCLUDED.sku,
          product_name = EXCLUDED.product_name,
          quantity = EXCLUDED.quantity,
          updated_at = NOW()
        RETURNING (xmax = 0) AS inserted
        `,
        [row.orderCode, row.sku, finalProductName, row.quantity, req.authUser?.username || null]
      );
      if (result.rows[0]?.inserted) inserted += 1;
      else updated += 1;
    }

    res.json({
      ok: true,
      message: `Import hoàn tất ${rows.length} dòng`,
      summary: { total: rows.length, inserted, updated, autoFilled, missingProductName }
    });
  } catch (error) {
    res.status(500).json({ ok: false, message: error.message });
  }
});

app.get('/api/qa/orders/:id/barcode', requireRole('qa'), async (req, res) => {
  try {
    const result = await pool.query('SELECT id, order_code FROM qa_orders WHERE id = $1 LIMIT 1', [
      Number(req.params.id)
    ]);
    if (!result.rows.length) {
      return res.status(404).send('Order not found');
    }

    const barcode = await bwipjs.toBuffer({
      bcid: 'code128',
      text: result.rows[0].order_code,
      scale: 3,
      height: 12,
      includetext: true,
      textxalign: 'center'
    });

    res.set('Content-Type', 'image/png');
    res.send(barcode);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

function serveRolePage(expectedRole, fileName) {
  return [
    requireOpsAuth,
    (req, res) => {
      if (req.authUser.role !== expectedRole) {
        return res.status(403).send('Forbidden');
      }
      return res.sendFile(require('path').join(process.cwd(), 'public', fileName));
    }
  ];
}

app.get('/roles/production-worker', ...serveRolePage('production_worker', 'production-worker.html'));
app.get('/roles/production-manager', ...serveRolePage('production_manager', 'production-manager.html'));
app.get('/roles/qa', ...serveRolePage('qa', 'qa.html'));
app.get('/roles/fabric-cutting-team', ...serveRolePage('fabric_cutting_team', 'fabric-cutting-team.html'));
app.get('/roles/cotton-press-team', ...serveRolePage('cotton_press_team', 'cotton-press-team.html'));
app.get('/roles/eyelet-team', ...serveRolePage('eyelet_team', 'eyelet-team.html'));
app.get('/roles/sewing-team', ...serveRolePage('sewing_team', 'sewing-team.html'));
app.get('/roles/assembly-team', ...serveRolePage('assembly_team', 'assembly-team.html'));

app.post('/logout', (_req, res) => {
  res.clearCookie('ops_auth');
  res.json({ ok: true });
});

app.get('/logout', (_req, res) => {
  res.clearCookie('ops_auth');
  return res.redirect(`${config.mainAppUrl}/login`);
});

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'operations-service' });
  } catch (error) {
    res.status(503).json({
      ok: false,
      service: 'operations-service',
      error: error.message
    });
  }
});

app.get('/api/operations/orders', requireOpsAuth, async (_req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        order_code,
        current_status,
        assigned_to_user_id,
        priority,
        metadata,
        created_at,
        updated_at
      FROM operation_orders
      ORDER BY updated_at DESC
      LIMIT 100
      `
    );
    res.json({ items: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/operations/orders', requireOpsAuth, async (req, res) => {
  const { orderCode, status, assignedToUserId, priority, metadata } = req.body;
  if (!orderCode) {
    return res.status(400).json({ error: 'orderCode is required' });
  }

  try {
    const result = await pool.query(
      `
      INSERT INTO operation_orders (
        order_code,
        current_status,
        assigned_to_user_id,
        priority,
        metadata
      ) VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (order_code)
      DO UPDATE SET
        current_status = EXCLUDED.current_status,
        assigned_to_user_id = EXCLUDED.assigned_to_user_id,
        priority = EXCLUDED.priority,
        metadata = EXCLUDED.metadata,
        updated_at = NOW()
      RETURNING *
      `,
      [
        orderCode,
        status || 'pending',
        assignedToUserId || null,
        Number.isInteger(priority) ? priority : 0,
        metadata || {}
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/operations/actions', requireOpsAuth, async (req, res) => {
  const { orderCode, actionType, byUserId, payload } = req.body;
  if (!orderCode || !actionType || !byUserId) {
    return res
      .status(400)
      .json({ error: 'orderCode, actionType and byUserId are required' });
  }

  try {
    const result = await pool.query(
      `
      INSERT INTO operation_actions (
        order_code,
        action_type,
        by_user_id,
        payload
      ) VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [orderCode, actionType, byUserId, payload || {}]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = app;
