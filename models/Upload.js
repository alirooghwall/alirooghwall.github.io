const mongoose = require('mongoose');

const uploadSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  mimetype: String,
  size: Number,
  url: String, // Cloud storage URL or local path
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  category: String, // e.g., 'profile', 'resource', 'report'
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Upload', uploadSchema);