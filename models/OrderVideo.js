const mongoose = require('mongoose');

const orderVideoSchema = new mongoose.Schema(
  {
    maVanDon: { type: String, required: true, index: true },
    userId: { type: String, default: null, index: true },
    comPort: { type: String, default: null },
    channel: { type: Number, default: null },
    rtspUrl: { type: String, default: null },

    status: {
      type: String,
      enum: ['recording', 'saved', 'discarded', 'failed'],
      required: true,
      default: 'recording',
      index: true
    },

    startedAt: { type: Date, required: true, default: Date.now, index: true },
    endedAt: { type: Date, default: null },

    tempRelativePath: { type: String, default: null },
    relativePath: { type: String, default: null },
    fileSizeBytes: { type: Number, default: null },
    durationMs: { type: Number, default: null },

    stopReason: { type: String, default: null },
    error: { type: String, default: null }
  },
  { timestamps: true }
);

orderVideoSchema.index({ maVanDon: 1, startedAt: -1 });

module.exports = mongoose.model('OrderVideo', orderVideoSchema);

