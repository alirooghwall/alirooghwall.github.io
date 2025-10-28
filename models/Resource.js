const mongoose = require('mongoose');

const resourceSchema = new mongoose.Schema({
  title: String,
  description: String,
  type: { type: String, enum: ['document', 'video', 'link', 'file'] },
  url: String,
  file: { filename: String, originalName: String },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  category: String,
  accessLevel: { type: String, enum: ['public', 'participants', 'managers'], default: 'public' },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Resource', resourceSchema);