(function () {
  const cfg = window.PRODUCTION_STAGE_CONFIG || {};
  const stageKey = cfg.stageKey;
  const stageLabel = cfg.stageLabel;
  const titleEl = document.getElementById("roleTitle");
  const subtitleEl = document.getElementById("roleSubtitle");
  const kpiEl = document.getElementById("kpiGrid");
  const tableBodyEl = document.getElementById("taskTableBody");
  const queueMessageEl = document.getElementById("queueMessage");
  const queueHintEl = document.getElementById("queueHint");
  const logoutBtn = document.getElementById("logoutBtn");
  const scanInput = document.getElementById("scanOrderCode");
  const scanBtn = document.getElementById("scanBtn");
  const scanMessageEl = document.getElementById("scanMessage");
  const recordSection = document.getElementById("recordSection");
  const orderInfoEl = document.getElementById("orderInfo");
  const completedQtyInput = document.getElementById("completedQtyInput");
  const defectQtyInput = document.getElementById("defectQtyInput");
  const noteInput = document.getElementById("noteInput");
  const submitRecordBtn = document.getElementById("submitRecordBtn");
  const recordMessageEl = document.getElementById("recordMessage");

  let currentOrder = null;
  /** @type {{ inboundCap?: number; inboundCapNote?: string; prevStageLabel?: string; stage?: string } | null} */
  let scanMeta = null;
  let html5QrcodeInstance = null;
  let scannerModalEl = null;
  let scannerClosing = false;

  if (titleEl) titleEl.textContent = cfg.title || "Công đoạn sản xuất";
  if (subtitleEl) subtitleEl.textContent = cfg.subtitle || "";
  if (queueHintEl) {
    queueHintEl.textContent =
      "Ưu tiên cao xếp trước. Sau khi ghi nhận, hệ thống chuyển đơn sang công đoạn kế tiếp trong luồng.";
  }

  function setQueueMsg(text, isError) {
    if (!queueMessageEl) return;
    queueMessageEl.textContent = text || "";
    queueMessageEl.style.color = isError ? "#b91c1c" : "var(--muted)";
  }

  function setScanMsg(text, isError) {
    if (!scanMessageEl) return;
    scanMessageEl.textContent = text || "";
    scanMessageEl.style.color = isError ? "#b91c1c" : "var(--muted)";
  }

  function setRecordMsg(text, isError) {
    if (!recordMessageEl) return;
    recordMessageEl.textContent = text || "";
    recordMessageEl.style.color = isError ? "#b91c1c" : "var(--muted)";
  }

  function ensureScannerModal() {
    if (document.getElementById("scannerModal")) {
      scannerModalEl = document.getElementById("scannerModal");
      return scannerModalEl;
    }
    const wrap = document.createElement("div");
    wrap.id = "scannerModal";
    wrap.className = "scanner-modal";
    wrap.setAttribute("role", "dialog");
    wrap.setAttribute("aria-modal", "true");
    wrap.setAttribute("aria-label", "Quét mã bằng camera");
    wrap.innerHTML =
      '<div class="scanner-modal__card">' +
      '<h3>Quét mã đơn</h3>' +
      '<p class="scanner-modal__hint">Cho phép trình duyệt truy cập camera. Đưa mã vạch hoặc QR vào khung. Cần HTTPS (hoặc localhost).</p>' +
      '<div id="qrReader"></div>' +
      '<div class="scanner-modal__actions">' +
      '<button type="button" class="btn-panel" id="scannerCloseBtn">Đóng</button>' +
      "</div></div>";
    document.body.appendChild(wrap);
    scannerModalEl = wrap;
    document.getElementById("scannerCloseBtn").addEventListener("click", function () {
      closeScanner();
    });
    wrap.addEventListener("click", function (e) {
      if (e.target === wrap) closeScanner();
    });
    return wrap;
  }

  async function closeScanner() {
    if (scannerClosing) return;
    scannerClosing = true;
    const modal = scannerModalEl || document.getElementById("scannerModal");
    if (html5QrcodeInstance) {
      try {
        await html5QrcodeInstance.stop();
      } catch (_) {}
      try {
        await html5QrcodeInstance.clear();
      } catch (_) {}
      html5QrcodeInstance = null;
    }
    if (modal) {
      modal.classList.remove("is-open");
      modal.setAttribute("aria-hidden", "true");
    }
    scannerClosing = false;
  }

  async function openScanner() {
    const Html5Qrcode = window.Html5Qrcode;
    if (!Html5Qrcode) {
      setScanMsg("Thư viện quét chưa tải. Kiểm tra mạng và tải lại trang.", true);
      return;
    }
    ensureScannerModal();
    scannerModalEl = document.getElementById("scannerModal");
    scannerModalEl.classList.add("is-open");
    scannerModalEl.setAttribute("aria-hidden", "false");
    setScanMsg("Đang mở camera…");

    const readerId = "qrReader";
    const boxW = Math.min(320, Math.floor(window.innerWidth - 48));
    const boxH = Math.max(100, Math.floor(boxW * 0.35));

    const F = window.Html5QrcodeSupportedFormats;
    const formatsToSupport = [];
    if (F) {
      if (F.CODE_128 != null) formatsToSupport.push(F.CODE_128);
      if (F.QR_CODE != null) formatsToSupport.push(F.QR_CODE);
      if (F.EAN_13 != null) formatsToSupport.push(F.EAN_13);
    }

    const config = {
      fps: 10,
      qrbox: { width: boxW, height: boxH },
      aspectRatio: 1.777778,
    };
    if (formatsToSupport.length) {
      config.formatsToSupport = formatsToSupport;
    }

    try {
      if (html5QrcodeInstance) {
        await closeScanner();
      }
      html5QrcodeInstance = new Html5Qrcode(readerId);

      let decodedOnce = false;
      const onOk = function (decodedText) {
        if (decodedOnce) return;
        const code = String(decodedText || "").trim();
        if (!code) return;
        decodedOnce = true;
        if (scanInput) scanInput.value = code;
        closeScanner().then(function () {
          setScanMsg("Đã quét mã, đang tìm đơn…");
          scanOrder();
        });
      };

      const noop = function () {};

      try {
        await html5QrcodeInstance.start({ facingMode: "environment" }, config, onOk, noop);
      } catch (e1) {
        const devices = await Html5Qrcode.getCameras();
        if (devices && devices.length) {
          const last = devices[devices.length - 1];
          await html5QrcodeInstance.start(last.id, config, onOk, noop);
        } else {
          throw e1;
        }
      }
      setScanMsg("Đã bật camera — đưa mã vào khung quét.");
    } catch (e) {
      setScanMsg(
        (e && e.message) || "Không mở được camera. Kiểm tra quyền truy cập hoặc dùng máy quét cầm tay.",
        true
      );
      await closeScanner();
    }
  }

  function attachCameraButton() {
    const row = document.querySelector(".scan-row");
    if (!row || document.getElementById("openScannerBtn")) return;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.id = "openScannerBtn";
    btn.className = "btn secondary btn-scan-camera";
    btn.textContent = "Camera quét";
    btn.setAttribute("aria-label", "Quét mã bằng camera");
    row.appendChild(btn);
    btn.addEventListener("click", function () {
      openScanner();
    });
  }

  async function loadQueue() {
    if (!stageKey) return;
    setQueueMsg("Đang tải…");
    try {
      const res = await fetch(`/api/production/orders/queue?stageKey=${encodeURIComponent(stageKey)}`);
      const data = await res.json();
      if (!data.success) throw new Error(data.message || "Không tải được hàng đợi");
      const items = data.items || [];
      const c = data.counts || {};
      if (kpiEl) {
        kpiEl.innerHTML = `
          <div class="kpi-card">
            <div class="kpi-title">Đơn chờ tại khâu</div>
            <div class="kpi-value">${c.total ?? items.length}</div>
            <div class="kpi-note">Theo công đoạn hiện tại</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-title">Ưu tiên cao</div>
            <div class="kpi-value">${c.highPriority ?? 0}</div>
            <div class="kpi-note">Xử lý trước</div>
          </div>
        `;
      }
      if (tableBodyEl) {
        tableBodyEl.innerHTML = items
          .map((row) => {
            const pr = row.priority === "high" ? "Cao" : "Thường";
            const badge = row.priority === "high" ? "warn" : "info";
            return `
            <tr>
              <td><span class="badge ${badge}">${pr}</span></td>
              <td>${row.orderCode}</td>
              <td>${row.sku}</td>
              <td>${row.productName}</td>
              <td>${row.quantity}</td>
              <td>${row.currentStage || "—"}</td>
              <td><span class="badge ${row.currentStatus === "completed" ? "ok" : "info"}">${row.currentStatus || "—"}</span></td>
            </tr>`;
          })
          .join("");
      }
      setQueueMsg(items.length ? `Có ${items.length} đơn` : "Không có đơn chờ tại khâu này");
    } catch (e) {
      setQueueMsg(e.message, true);
    }
  }

  function showOrderForRecord(order, meta) {
    currentOrder = order;
    scanMeta = meta && typeof meta === "object" ? meta : null;
    const cap =
      scanMeta && Number.isFinite(Number(scanMeta.inboundCap))
        ? Number(scanMeta.inboundCap)
        : Number(order.quantity || 0);
    const capLine =
      scanMeta && scanMeta.inboundCapNote
        ? String(scanMeta.inboundCapNote)
        : `Tối đa (SL đơn): ${order.quantity}`;
    if (recordSection) recordSection.style.display = "";
    if (orderInfoEl) {
      orderInfoEl.innerHTML = `
        <div><strong>Mã đơn:</strong> ${order.orderCode}</div>
        <div><strong>SKU / SP:</strong> ${order.sku} — ${order.productName}</div>
        <div><strong>SL đơn (PO):</strong> ${order.quantity} &nbsp;|&nbsp; <strong>Giới hạn ghi nhận:</strong> tổng (hoàn thành + lỗi) ≤ ${cap}</div>
        <div class="helper" style="margin-top:4px;">${capLine}</div>
        <div><strong>Công đoạn ghi nhận:</strong> ${stageLabel}</div>
      `;
    }
    if (completedQtyInput) completedQtyInput.value = "";
    if (defectQtyInput) defectQtyInput.value = "";
    if (noteInput) noteInput.value = "";
    setRecordMsg("");
  }

  function bindNaturalQtyInputs() {
    function stripNonDigits(el) {
      if (!el) return;
      el.setAttribute("inputmode", "numeric");
      el.setAttribute("pattern", "[0-9]*");
      el.autocomplete = "off";
      el.addEventListener("input", function () {
        const v = String(el.value || "").replace(/\D/g, "");
        if (el.value !== v) el.value = v;
      });
      el.addEventListener("paste", function (e) {
        e.preventDefault();
        const t = (e.clipboardData && e.clipboardData.getData("text")) || "";
        el.value = String(t).replace(/\D/g, "");
      });
    }
    stripNonDigits(completedQtyInput);
    stripNonDigits(defectQtyInput);
  }

  function parseNaturalQty(value, label) {
    const s = String(value == null ? "" : value).trim();
    if (s === "") {
      if (label === "Số lượng lỗi") return 0;
      throw new Error(`${label}: bắt buộc nhập số tự nhiên (chỉ 0–9)`);
    }
    if (!/^\d+$/.test(s)) {
      throw new Error(`${label}: chỉ được nhập số tự nhiên, không chữ hoặc ký tự đặc biệt`);
    }
    const n = parseInt(s, 10);
    if (n > Number.MAX_SAFE_INTEGER) throw new Error(`${label}: số quá lớn`);
    return n;
  }

  async function scanOrder() {
    const orderCode = (scanInput && scanInput.value.trim()) || "";
    if (!orderCode) {
      setScanMsg("Nhập hoặc quét mã đơn", true);
      return;
    }
    setScanMsg("Đang tìm…");
    try {
      const res = await fetch("/api/production/orders/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ orderCode }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message || "Không tìm thấy đơn");
      const order = data.item;
      const cur = String(order.currentStage || "").trim();
      const ok =
        stageLabel === "Cắt vải"
          ? cur === "Tạo đơn" || cur === "Cắt vải"
          : cur === stageLabel;
      if (!ok) {
        setScanMsg(`Đơn đang ở công đoạn «${cur || "—"}», không khớp khâu ${stageLabel}.`, true);
        currentOrder = null;
        if (recordSection) recordSection.style.display = "none";
        return;
      }
      setScanMsg(`Đã mở đơn ${order.orderCode}`);
      showOrderForRecord(order, data.meta);
    } catch (e) {
      setScanMsg(e.message, true);
      currentOrder = null;
      if (recordSection) recordSection.style.display = "none";
    }
  }

  async function submitRecord() {
    if (!currentOrder) {
      setRecordMsg("Quét đơn trước khi ghi nhận", true);
      return;
    }
    const qtyTotal = Number(currentOrder.quantity || 0);
    let done;
    let defect;
    try {
      done = parseNaturalQty(completedQtyInput && completedQtyInput.value, "Số lượng hoàn thành");
      defect = parseNaturalQty(defectQtyInput && defectQtyInput.value, "Số lượng lỗi");
    } catch (err) {
      setRecordMsg(err.message || "Dữ liệu không hợp lệ", true);
      return;
    }

    if (!Number.isFinite(qtyTotal) || qtyTotal <= 0) {
      setRecordMsg("Số lượng đơn không hợp lệ", true);
      return;
    }
    if (defect > 0 && !(noteInput && String(noteInput.value).trim())) {
      setRecordMsg("Có số lượng lỗi thì bắt buộc nhập lý do lỗi (ghi chú)", true);
      return;
    }
    if (done + defect <= 0) {
      setRecordMsg("Tổng SL hoàn thành + lỗi phải lớn hơn 0", true);
      return;
    }
    const cap =
      scanMeta && Number.isFinite(Number(scanMeta.inboundCap)) ? Number(scanMeta.inboundCap) : qtyTotal;
    if (done + defect > cap) {
      setRecordMsg(`SL hoàn thành + SL lỗi (${done + defect}) không được vượt đầu vào khâu trước (${cap}). Hãy quét lại mã để cập nhật giới hạn.`, true);
      return;
    }
    setRecordMsg("Đang lưu…");
    try {
      const res = await fetch("/api/production/orders/update-status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          orderCode: currentOrder.orderCode,
          stage: stageLabel,
          completedQty: done,
          defectQty: defect,
          note: (noteInput && noteInput.value.trim()) || "",
        }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message || "Lưu thất bại");
      setRecordMsg(data.message || "Đã ghi nhận");
      if (scanInput) scanInput.value = "";
      currentOrder = null;
      if (recordSection) recordSection.style.display = "none";
      await loadQueue();
    } catch (e) {
      setRecordMsg(e.message, true);
    }
  }

  if (scanBtn) scanBtn.addEventListener("click", scanOrder);
  if (scanInput) {
    scanInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        scanOrder();
      }
    });
  }
  if (submitRecordBtn) submitRecordBtn.addEventListener("click", submitRecord);

  bindNaturalQtyInputs();
  attachCameraButton();

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async function () {
      try {
        await fetch("/api/logout", { method: "POST" });
      } catch (_) {}
      window.location.href = "/login";
    });
  }

  document.addEventListener(
    "visibilitychange",
    function () {
      if (document.visibilityState === "hidden") {
        closeScanner();
      }
    },
    false
  );

  loadQueue();
})();
