const mongoose = require('mongoose');

const profileUpdateRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  requestedChanges: {
    name: String,
    email: String,
    phone: String,
    leaderName: String,
    mlmLevel: String
  },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('ProfileUpdateRequest', profileUpdateRequestSchema);