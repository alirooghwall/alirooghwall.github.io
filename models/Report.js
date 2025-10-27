const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  title: String,
  type: { type: String, enum: ['user_activity', 'sales', 'recruitment', 'system'] },
  data: mongoose.Schema.Types.Mixed, // Flexible data structure
  generatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Report', reportSchema);