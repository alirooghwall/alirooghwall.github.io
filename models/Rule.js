const mongoose = require('mongoose');

const ruleSchema = new mongoose.Schema({
  title: String,
  content: String,
  category: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Rule', ruleSchema);