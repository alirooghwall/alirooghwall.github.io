const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  level: { type: String, enum: ['info', 'warn', 'error'] },
  message: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  details: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Log', logSchema);