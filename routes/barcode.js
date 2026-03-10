const express = require('express');
const bwipjs = require('bwip-js');
const PDFDocument = require('pdfkit');

const router = express.Router();

// Generate a barcode PNG for printing/capturing.
// Example: /api/barcode?text=CV-MAUM001-1234567890
router.get('/api/barcode', async (req, res) => {
  try {
    const textRaw = (req.query.text ?? '').toString();
    const text = textRaw.trim();

    if (!text) {
      return res.status(400).json({ success: false, message: 'Thiếu tham số text' });
    }

    const png = await bwipjs.toBuffer({
      bcid: 'code128',
      text,
      scale: 3,
      height: 10,
      includetext: true,
      textxalign: 'center',
      backgroundcolor: 'FFFFFF',
    });

    res.set('Content-Type', 'image/png');
    // allow browser cache per text
    res.set('Cache-Control', 'public, max-age=86400');
    return res.send(png);
  } catch (error) {
    console.error('[BARCODE] Error generating barcode:', error);
    return res.status(500).json({ success: false, message: 'Không thể tạo mã vạch' });
  }
});

// Generate a PDF that contains multiple barcodes (for printing/capturing).
// Body: { ids: ["CV-...","CV-..."] }
router.post('/api/barcodes/pdf', express.json({ limit: '1mb' }), async (req, res) => {
  try {
    const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
    const cleaned = Array.from(
      new Set(
        ids
          .map((x) => (x ?? '').toString().trim())
          .filter((x) => x.length > 0)
      )
    );

    if (cleaned.length === 0) {
      return res.status(400).json({ success: false, message: 'Không có danh sách ID để tạo PDF' });
    }

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="barcode_doi_tuong_cat_${Date.now()}.pdf"`
    );

    const doc = new PDFDocument({ size: 'A4', margin: 28 });
    doc.pipe(res);

    // Layout: 2 columns x 4 rows per page (8 barcodes/page)
    const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;
    const pageHeight = doc.page.height - doc.page.margins.top - doc.page.margins.bottom;
    const cols = 2;
    const rows = 4;
    const cellW = pageWidth / cols;
    const cellH = pageHeight / rows;

    for (let i = 0; i < cleaned.length; i++) {
      if (i > 0 && i % (cols * rows) === 0) {
        doc.addPage();
      }

      const idxInPage = i % (cols * rows);
      const col = idxInPage % cols;
      const row = Math.floor(idxInPage / cols);

      const x0 = doc.page.margins.left + col * cellW;
      const y0 = doc.page.margins.top + row * cellH;

      const id = cleaned[i];

      const png = await bwipjs.toBuffer({
        bcid: 'code128',
        text: id,
        scale: 3,
        height: 10,
        includetext: true,
        textxalign: 'center',
        backgroundcolor: 'FFFFFF',
        paddingwidth: 10,
        paddingheight: 10,
      });

      // Draw a light border for cutting/visual separation
      doc
        .save()
        .lineWidth(0.5)
        .strokeColor('#d1d5db')
        .rect(x0 + 6, y0 + 6, cellW - 12, cellH - 12)
        .stroke()
        .restore();

      // Fit barcode image inside cell
      const imgMaxW = cellW - 28;
      const imgMaxH = cellH - 28;
      doc.image(png, x0 + 14, y0 + 14, { fit: [imgMaxW, imgMaxH], align: 'center', valign: 'center' });
    }

    doc.end();
  } catch (error) {
    console.error('[BARCODES PDF] Error:', error);
    if (!res.headersSent) {
      return res.status(500).json({ success: false, message: 'Không thể tạo PDF mã vạch' });
    }
    // If headers already sent, just end the response
    return res.end();
  }
});

module.exports = router;

