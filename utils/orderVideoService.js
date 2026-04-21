const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');
const dotenv = require('dotenv');
const config = require('../config');
let ffmpegPath = null;
try {
  // eslint-disable-next-line global-require
  ffmpegPath = require('ffmpeg-static');
} catch {
  ffmpegPath = null;
}

const OrderVideo = require('../models/OrderVideo');

const VIDEO_DIR_NAME = 'order-videos';
const VIDEO_ROOT_DIR = path.join(__dirname, '..', VIDEO_DIR_NAME);
const ROOT_ENV_PATH = path.join(__dirname, '..', '.env');
const VIDEO_SERVICE_VERSION = 'video-flow-fix-v3';

const active = new Map(); // key: maVanDon -> { proc, docId, tempAbsPath, finalAbsPath, startedAtMs, timeoutId }

function safeSlug(input) {
  return String(input || '')
    .trim()
    .replace(/[^\p{L}\p{N}\-_]+/gu, '_')
    .slice(0, 80);
}

function parseComChannelMapFromEnv() {
  const raw = process.env.VIDEO_COM_CHANNEL_MAP || config.VIDEO_COM_CHANNEL_MAP;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    const normalized = {};
    for (const [k, v] of Object.entries(parsed)) {
      const key = String(k || '').toUpperCase();
      const num = Number(v);
      if (!key || !Number.isFinite(num)) continue;
      normalized[key] = num;
    }
    return normalized;
  } catch {
    return null;
  }
}

function getRtspUrlForChannel(channel) {
  const ch = Number(channel);
  if (!Number.isFinite(ch)) return null;
  const fromEnv = (key) => {
    const v = process.env[key];
    return v && String(v).trim() ? String(v).trim() : null;
  };
  const fromConfig = (key) => {
    const v = config[key];
    return v && String(v).trim() ? String(v).trim() : null;
  };
  const fromDotEnvFile = (key) => {
    try {
      const raw = fs.readFileSync(ROOT_ENV_PATH, 'utf8');
      const parsed = dotenv.parse(raw);
      const v = parsed[key];
      return v && String(v).trim() ? String(v).trim() : null;
    } catch {
      return null;
    }
  };

  if (ch === 1) {
    return fromEnv('CAM_RTSP_CHANNEL_1')
      || fromConfig('CAM_RTSP_CHANNEL_1')
      || fromDotEnvFile('CAM_RTSP_CHANNEL_1')
      || null;
  }
  if (ch === 2) {
    return fromEnv('CAM_RTSP_CHANNEL_2')
      || fromConfig('CAM_RTSP_CHANNEL_2')
      || fromDotEnvFile('CAM_RTSP_CHANNEL_2')
      || null;
  }
  return fromEnv(`CAM_RTSP_CHANNEL_${ch}`)
    || fromConfig(`CAM_RTSP_CHANNEL_${ch}`)
    || fromDotEnvFile(`CAM_RTSP_CHANNEL_${ch}`)
    || null;
}

function getRtspDebugForChannel(channel) {
  const ch = Number(channel);
  const key = `CAM_RTSP_CHANNEL_${ch}`;
  const fromEnvRaw = process.env[key];
  const fromConfigRaw = config[key];
  let fromDotEnvRaw = null;
  try {
    const raw = fs.readFileSync(ROOT_ENV_PATH, 'utf8');
    const parsed = dotenv.parse(raw);
    fromDotEnvRaw = parsed[key] || null;
  } catch {
    fromDotEnvRaw = null;
  }

  const preview = (v) => {
    if (!v || !String(v).trim()) return null;
    const s = String(v).trim();
    if (s.length <= 35) return s;
    return `${s.slice(0, 24)}...${s.slice(-8)}`;
  };

  return {
    key,
    envPath: ROOT_ENV_PATH,
    envHasValue: !!(fromEnvRaw && String(fromEnvRaw).trim()),
    configHasValue: !!(fromConfigRaw && String(fromConfigRaw).trim()),
    dotEnvHasValue: !!(fromDotEnvRaw && String(fromDotEnvRaw).trim()),
    envPreview: preview(fromEnvRaw),
    configPreview: preview(fromConfigRaw),
    dotEnvPreview: preview(fromDotEnvRaw)
  };
}

async function ensureVideoDir() {
  await fsp.mkdir(VIDEO_ROOT_DIR, { recursive: true });
}

function buildPaths(maVanDon, channel) {
  const now = new Date();
  const ts =
    `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-` +
    `${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`;
  const base = `${safeSlug(maVanDon)}__ch${channel || 'na'}__${ts}`;
  const tempFile = `${base}.tmp.mp4`;
  const finalFile = `${base}.mp4`;
  return {
    tempRelativePath: path.join(VIDEO_DIR_NAME, tempFile),
    relativePath: path.join(VIDEO_DIR_NAME, finalFile),
    tempAbsPath: path.join(VIDEO_ROOT_DIR, tempFile),
    finalAbsPath: path.join(VIDEO_ROOT_DIR, finalFile)
  };
}

function waitForExit(proc, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const t = setTimeout(() => {
      if (done) return;
      done = true;
      resolve({ exitCode: null, signal: 'timeout' });
    }, timeoutMs);

    proc.once('exit', (code, signal) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      resolve({ exitCode: code, signal });
    });
  });
}

async function fileSizeOrNull(absPath) {
  try {
    const stat = await fsp.stat(absPath);
    return stat.size;
  } catch {
    return null;
  }
}

async function fileExists(absPath) {
  try {
    await fsp.access(absPath);
    return true;
  } catch {
    return false;
  }
}

async function safeUnlink(absPath) {
  try {
    await fsp.unlink(absPath);
  } catch {
    // ignore
  }
}

async function startRecordingForVanDon({ maVanDon, userId, comPort, videoChannel = null }) {
  const key = String(maVanDon || '').trim();
  if (!key) return { started: false, reason: 'missing_maVanDon' };
  if (active.has(key)) return { started: false, reason: 'already_recording' };

  const comMap = parseComChannelMapFromEnv() || { COM14: 1, COM8: 2 };
  const normalizedCom = comPort ? String(comPort).toUpperCase() : null;
  const preferredChannel = Number(videoChannel);
  const channel = Number.isFinite(preferredChannel) && preferredChannel > 0
    ? preferredChannel
    : (normalizedCom ? (comMap[normalizedCom] || null) : null);
  const rtspUrl = channel ? getRtspUrlForChannel(channel) : null;

  // Nếu chưa có rtspUrl thì không record để tránh ghi sai nguồn
  if (!rtspUrl) {
    return {
      started: false,
      reason: 'missing_rtsp',
      channel,
      comPort: normalizedCom,
      debug: {
        requested: {
          maVanDon: key,
          userId: userId || null,
          videoChannel: Number.isFinite(preferredChannel) ? preferredChannel : null,
          comPort: normalizedCom
        },
        rtsp: channel ? getRtspDebugForChannel(channel) : null
      }
    };
  }

  await ensureVideoDir();

  const { tempRelativePath, relativePath, tempAbsPath, finalAbsPath } = buildPaths(key, channel);

  const doc = await OrderVideo.create({
    maVanDon: key,
    userId: userId || null,
    comPort: normalizedCom || null,
    channel: channel || null,
    rtspUrl,
    status: 'recording',
    startedAt: new Date(),
    tempRelativePath,
    relativePath: null
  });

  // Ghi MP4 fragment để giảm rủi ro moov chưa ghi khi dừng
  const args = [
    '-hide_banner',
    '-loglevel',
    'error',
    '-rtsp_transport',
    'tcp',
    '-i',
    rtspUrl,
    '-an',
    '-c:v',
    'copy',
    '-movflags',
    '+frag_keyframe+empty_moov+faststart',
    '-f',
    'mp4',
    '-y',
    tempAbsPath
  ];

  const ffmpegBin = ffmpegPath || 'ffmpeg';
  const proc = spawn(ffmpegBin, args, { windowsHide: true });
  const stderrChunks = [];

  if (proc.stderr) {
    proc.stderr.on('data', (chunk) => {
      try {
        const s = String(chunk || '');
        if (s) stderrChunks.push(s);
      } catch {
        // ignore
      }
    });
  }

  proc.on('error', async (err) => {
    try {
      await OrderVideo.updateOne(
        { _id: doc._id },
        { $set: { status: 'failed', endedAt: new Date(), error: String(err?.message || err) } }
      );
    } catch {
      // ignore
    }
    active.delete(key);
    await safeUnlink(tempAbsPath);
  });

  // Auto-stop safeguard (25 phút)
  const startedAtMs = Date.now();
  const timeoutId = setTimeout(() => {
    // best-effort discard nếu quá lâu
    stopAndDiscardRecording(key, { reason: 'timeout_auto_discard' }).catch(() => {});
  }, 25 * 60 * 1000);

  active.set(key, {
    proc,
    docId: doc._id.toString(),
    tempAbsPath,
    finalAbsPath,
    startedAtMs,
    timeoutId,
    stderrChunks
  });

  return { started: true, channel, comPort: normalizedCom, docId: doc._id.toString() };
}

async function stopAndSaveRecording(maVanDon, { reason = 'completed', userId = null } = {}) {
  const key = String(maVanDon || '').trim();
  const entry = active.get(key);
  if (!entry) {
    return { stopped: false, reason: 'not_recording' };
  }

  active.delete(key);
  clearTimeout(entry.timeoutId);

  const endedAt = new Date();
  const durationMs = Date.now() - entry.startedAtMs;

  try {
    // SIGINT để ffmpeg flush moov tốt hơn
    entry.proc.kill('SIGINT');
  } catch {
    // ignore
  }

  const { exitCode } = await waitForExit(entry.proc, 12_000);
  if (exitCode === null) {
    try {
      entry.proc.kill('SIGKILL');
    } catch {
      // ignore
    }
    await waitForExit(entry.proc, 3_000);
  }

  const stderrPreview = entry.stderrChunks && entry.stderrChunks.length
    ? entry.stderrChunks.join('').slice(0, 2000)
    : null;

  const tempExists = await fileExists(entry.tempAbsPath);
  if (!tempExists) {
    await OrderVideo.updateOne(
      { _id: entry.docId },
      {
        $set: {
          status: 'failed',
          endedAt,
          durationMs,
          fileSizeBytes: null,
          stopReason: reason,
          error: `ffmpeg_no_output exit_code=${exitCode === null ? 'null' : exitCode}${stderrPreview ? ` stderr=${stderrPreview}` : ''}`
        }
      }
    );
    return { stopped: true, saved: false, reason: 'ffmpeg_no_output' };
  }

  // Rename .part -> .mp4 (nếu file tồn tại)
  try {
    await fsp.rename(entry.tempAbsPath, entry.finalAbsPath);
  } catch {
    // nếu rename fail thì vẫn cố lưu trạng thái failed
    const size = await fileSizeOrNull(entry.tempAbsPath);
    await OrderVideo.updateOne(
      { _id: entry.docId },
      {
        $set: {
          status: 'failed',
          endedAt,
          durationMs,
          fileSizeBytes: size,
          stopReason: reason,
          error: `rename_failed exit_code=${exitCode === null ? 'null' : exitCode}${stderrPreview ? ` stderr=${stderrPreview}` : ''}`
        }
      }
    );
    return { stopped: true, saved: false, reason: 'rename_failed' };
  }

  const size = await fileSizeOrNull(entry.finalAbsPath);
  await OrderVideo.updateOne(
    { _id: entry.docId },
    {
      $set: {
        status: 'saved',
        endedAt,
        durationMs,
        fileSizeBytes: size,
        relativePath: path.join(VIDEO_DIR_NAME, path.basename(entry.finalAbsPath)),
        stopReason: reason,
        ...(userId ? { userId } : {})
      }
    }
  );

  return { stopped: true, saved: true };
}

async function stopAndDiscardRecording(maVanDon, { reason = 'discarded' } = {}) {
  const key = String(maVanDon || '').trim();
  const entry = active.get(key);
  if (!entry) {
    return { stopped: false, reason: 'not_recording' };
  }

  active.delete(key);
  clearTimeout(entry.timeoutId);

  const endedAt = new Date();
  const durationMs = Date.now() - entry.startedAtMs;

  try {
    entry.proc.kill('SIGINT');
  } catch {
    // ignore
  }
  const { exitCode } = await waitForExit(entry.proc, 6_000);
  if (exitCode === null) {
    try {
      entry.proc.kill('SIGKILL');
    } catch {
      // ignore
    }
    await waitForExit(entry.proc, 2_000);
  }

  await safeUnlink(entry.tempAbsPath);
  await safeUnlink(entry.finalAbsPath);

  await OrderVideo.updateOne(
    { _id: entry.docId },
    { $set: { status: 'discarded', endedAt, durationMs, stopReason: reason } }
  );

  return { stopped: true, discarded: true };
}

async function findLatestSavedVideo(maVanDon) {
  const key = String(maVanDon || '').trim();
  if (!key) return null;
  return OrderVideo.findOne({ maVanDon: key, status: 'saved' }).sort({ startedAt: -1 }).lean();
}

function resolveVideoAbsPathFromDoc(doc) {
  if (!doc || !doc.relativePath) return null;
  const rel = String(doc.relativePath);
  // Ensure it stays under VIDEO_ROOT_DIR
  const abs = path.resolve(path.join(__dirname, '..', rel));
  if (!abs.startsWith(path.resolve(VIDEO_ROOT_DIR))) return null;
  return abs;
}

module.exports = {
  startRecordingForVanDon,
  stopAndSaveRecording,
  stopAndDiscardRecording,
  findLatestSavedVideo,
  resolveVideoAbsPathFromDoc,
  getRtspUrlForChannel,
  getRtspDebugForChannel,
  VERSION: VIDEO_SERVICE_VERSION,
  getDebugInfo: () => ({
    version: VIDEO_SERVICE_VERSION,
    ffmpegPath: ffmpegPath || null,
    hasFfmpegStatic: !!ffmpegPath,
    cwd: process.cwd(),
    envPath: ROOT_ENV_PATH,
    videoRootDir: VIDEO_ROOT_DIR,
    env: {
      VIDEO_COM_CHANNEL_MAP: process.env.VIDEO_COM_CHANNEL_MAP || config.VIDEO_COM_CHANNEL_MAP || null,
      CAM_RTSP_CHANNEL_1: (process.env.CAM_RTSP_CHANNEL_1 || config.CAM_RTSP_CHANNEL_1) ? 'set' : null,
      CAM_RTSP_CHANNEL_2: (process.env.CAM_RTSP_CHANNEL_2 || config.CAM_RTSP_CHANNEL_2) ? 'set' : null
    },
    resolved: {
      ch1: getRtspUrlForChannel(1) ? 'set' : null,
      ch2: getRtspUrlForChannel(2) ? 'set' : null
    }
  })
};

