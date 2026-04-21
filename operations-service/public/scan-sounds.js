/**
 * Âm thanh phản hồi khi quét mã (đơn / SP / lỗi).
 * - Mặc định: Web Audio API (không cần file).
 * - Tùy chọn: đặt file MP3 vào public/sounds/ — nếu load được sẽ ưu tiên file.
 *
 * Mapping gợi ý:
 *   order_ok      — mã vận đơn / đơn hợp lệ, check-in thành công
 *   item_ok       — quét đúng mã hàng (SP) trong đơn
 *   item_wrong    — SP sai, không thuộc đơn, hoặc sai công đoạn (sản xuất)
 *   order_cancel  — hủy đơn
 *   not_found     — không tìm thấy mã đơn / đơn không tồn tại
 *   order_complete — hoàn tất đơn (kiểm đơn)
 *   warning       — cảnh báo nhẹ (vd. đơn đã quét xong)
 */
(function (global) {
  "use strict";

  /** Thử phát file; nếu không có hoặc lỗi → false */
  var FILE_MAP = {
    order_ok: "/sounds/correct.mp3",
    item_ok: "/sounds/correct-pr.mp3",
    item_wrong: "/sounds/fail.mp3",
    order_cancel: "/sounds/fail.mp3",
    not_found: "/sounds/fail.mp3",
    order_complete: "/sounds/correct.mp3",
    warning: "/sounds/fail.mp3",
    stage_wrong: "/sounds/fail.mp3",
  };

  var ctx = null;

  function getCtx() {
    if (!ctx) {
      var Ctx = global.AudioContext || global.webkitAudioContext;
      if (!Ctx) return null;
      ctx = new Ctx();
    }
    if (ctx.state === "suspended") {
      ctx.resume().catch(function () {});
    }
    return ctx;
  }

  function playTone(c, freq, t0, dur, type, gain) {
    var osc = c.createOscillator();
    var g = c.createGain();
    osc.type = type || "sine";
    osc.frequency.setValueAtTime(freq, t0);
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(gain || 0.22, t0 + 0.012);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    osc.connect(g);
    g.connect(c.destination);
    osc.start(t0);
    osc.stop(t0 + dur + 0.02);
  }

  function playBuiltin(kind) {
    var c = getCtx();
    if (!c) return;
    var now = c.currentTime;

    switch (kind) {
      case "order_ok":
        playTone(c, 523.25, now, 0.09, "sine", 0.2);
        playTone(c, 659.25, now + 0.11, 0.11, "sine", 0.22);
        break;
      case "item_ok":
        playTone(c, 784, now, 0.11, "sine", 0.24);
        break;
      case "item_wrong":
      case "stage_wrong":
        playTone(c, 185, now, 0.14, "triangle", 0.28);
        playTone(c, 165, now + 0.22, 0.18, "triangle", 0.3);
        break;
      case "order_cancel":
        playTone(c, 392, now, 0.1, "sine", 0.2);
        playTone(c, 261.63, now + 0.12, 0.16, "sine", 0.22);
        break;
      case "not_found":
        playTone(c, 110, now, 0.22, "sawtooth", 0.18);
        break;
      case "order_complete":
        playTone(c, 523.25, now, 0.08, "sine", 0.2);
        playTone(c, 659.25, now + 0.1, 0.08, "sine", 0.2);
        playTone(c, 783.99, now + 0.2, 0.14, "sine", 0.24);
        break;
      case "warning":
        playTone(c, 440, now, 0.07, "sine", 0.18);
        playTone(c, 330, now + 0.12, 0.1, "sine", 0.16);
        break;
      default:
        playTone(c, 330, now, 0.08, "sine", 0.15);
    }
  }

  function playFromFile(kind, onFail) {
    var src = FILE_MAP[kind];
    if (!src) {
      onFail();
      return;
    }
    var a = new Audio(src);
    a.volume = 0.88;
    var p = a.play();
    if (p && typeof p.then === "function") {
      p.then(function () {}).catch(function () {
        onFail();
      });
    }
  }

  function playScanSound(kind) {
    if (!kind) return;
    playFromFile(kind, function () {
      playBuiltin(kind);
    });
  }

  /**
   * Gọi từ thao tác người dùng (click nút kết nối COM, nhấn Enter ô quét, …).
   * Web Serial gửi mã qua callback + setTimeout → không được coi là gesture, nên
   * AudioContext/HTML audio thường bị khóa cho đến khi unlock ở đây.
   */
  function unlockScanAudio() {
    var c = getCtx();
    if (!c) return;
    try {
      if (c.state === "suspended") {
        c.resume().catch(function () {});
      }
      var buf = c.createBuffer(1, 1, c.sampleRate);
      var src = c.createBufferSource();
      src.buffer = buf;
      src.connect(c.destination);
      src.start(0);
    } catch (e) {}
  }

  global.playScanSound = playScanSound;
  global.unlockScanAudio = unlockScanAudio;
})(typeof window !== "undefined" ? window : this);
